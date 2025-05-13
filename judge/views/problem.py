import logging
import os
import shutil
import zipfile
from datetime import timedelta
from operator import itemgetter
from random import randrange

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import (LoginRequiredMixin,
                                        PermissionRequiredMixin)
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.db import transaction
from django.db.models import F, Prefetch, Q
from django.db.utils import ProgrammingError
from django.http import (Http404, HttpResponse, HttpResponseBadRequest,
                         HttpResponseForbidden, HttpResponseRedirect)
from django.shortcuts import get_object_or_404
from django.template.loader import get_template
from django.urls import reverse
from django.utils import timezone, translation
from django.utils.functional import cached_property
from django.utils.html import escape, format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.generic import CreateView, ListView, UpdateView, View
from django.views.generic.base import TemplateResponseMixin
from django.views.generic.detail import SingleObjectMixin
from reversion import revisions

from judge.comments import CommentedDetailView
from judge.forms import (CreatePublicSolutionForm, ProblemCloneForm,
                         ProblemCreateForm, ProblemSubmitForm,
                         ProblemUpdateForm)
from judge.models import (ContestSubmission, Judge, Language, Problem,
                          ProblemGroup, ProblemTranslation, ProblemType,
                          Profile, RuntimeVersion, Solution, Submission,
                          SubmissionSource)
from judge.models.contest import Contest
from judge.models.problem_data import PublicSolution, SolutionVote
from judge.pdf_problems import HAS_PDF, DefaultPdfMaker
from judge.utils.diggpaginator import DiggPaginator
from judge.utils.opengraph import generate_opengraph
from judge.utils.problems import (contest_attempted_ids, contest_completed_ids,
                                  hot_problems, user_attempted_ids,
                                  user_completed_ids)
from judge.utils.strings import safe_int_or_none
from judge.utils.tickets import own_ticket_filter
from judge.utils.views import (DiggPaginatorMixin, QueryStringSortMixin,
                               SingleObjectFormView, TitleMixin,
                               add_file_response, generic_message)
from judge.views.widgets import submission_uploader


def get_contest_problem(problem, profile):
    try:
        return problem.contests.get(contest_id=profile.current_contest.contest_id)
    except ObjectDoesNotExist:
        return None


def get_contest_submission_count(problem, profile, virtual):
    return profile.current_contest.submissions.exclude(submission__status__in=['IE']) \
                  .filter(problem__problem=problem, participation__virtual=virtual).count()


class ProblemMixin(object):
    model = Problem
    slug_url_kwarg = 'problem'
    slug_field = 'code'

    def get_object(self, queryset=None):
        problem = super(ProblemMixin, self).get_object(queryset)
        if not problem.is_accessible_by(self.request.user):
            raise Http404()
        return problem

    def no_such_problem(self):
        code = self.kwargs.get(self.slug_url_kwarg, None)
        return generic_message(self.request, _('No such problem'),
                               _('Could not find a problem with the code "%s".') % code, status=404)

    def get(self, request, *args, **kwargs):
        if request.in_contest:
            if not request.user.is_superuser:
                return self.no_such_problem()

        try:
            return super(ProblemMixin, self).get(request, *args, **kwargs)
        except Http404:
            return self.no_such_problem()


class SolvedProblemMixin(object):
    def get_completed_problems(self):
        if self.in_contest:
            return contest_completed_ids(self.profile.current_contest)
        else:
            return user_completed_ids(self.profile) if self.profile is not None else ()

    def get_attempted_problems(self):
        if self.in_contest:
            return contest_attempted_ids(self.profile.current_contest)
        else:
            return user_attempted_ids(self.profile) if self.profile is not None else ()

    @cached_property
    def in_contest(self):
        return self.profile is not None and self.profile.current_contest is not None

    @cached_property
    def contest(self):
        return self.request.profile.current_contest.contest

    @cached_property
    def profile(self):
        if not self.request.user.is_authenticated:
            return None
        return self.request.profile


class ProblemSolution(SolvedProblemMixin, ProblemMixin, TitleMixin, CommentedDetailView):
    context_object_name = 'problem'
    template_name = 'problem/editorial.html'

    def get_title(self):
        return _('Editorial for {0}').format(self.object.name)

    def get_content_title(self):
        return format_html(_(u'Editorial for <a href="{1}">{0}</a>'), self.object.name,
                           reverse('problem_detail', args=[self.object.code]))

    def get_context_data(self, **kwargs):
        context = super(ProblemSolution, self).get_context_data(**kwargs)

        solution = get_object_or_404(Solution, problem=self.object)

        if not solution.is_accessible_by(self.request.user) or self.request.in_contest:
            raise Http404()
        context['solution'] = solution
        context['has_solved_problem'] = self.object.id in self.get_completed_problems()
        return context

    def get_comment_page(self):
        return 's:' + self.object.code

    def no_such_problem(self):
        code = self.kwargs.get(self.slug_url_kwarg, None)
        return generic_message(self.request, _('No such editorial'),
                               _('Could not find an editorial with the code "%s".') % code, status=404)


class ProblemRaw(ProblemMixin, TitleMixin, TemplateResponseMixin, SingleObjectMixin, View):
    context_object_name = 'problem'
    template_name = 'problem/raw.html'

    def get_title(self):
        return self.object.name

    def get_context_data(self, **kwargs):
        context = super(ProblemRaw, self).get_context_data(**kwargs)
        context['problem_name'] = self.object.name
        context['url'] = self.request.build_absolute_uri()
        context['description'] = self.object.description
        return context

    def get(self, request, *args, **kwargs):
        self.object = self.get_object()
        with translation.override(settings.LANGUAGE_CODE):
            return self.render_to_response(self.get_context_data(
                object=self.object,
            ))


class ProblemDetail(ProblemMixin, SolvedProblemMixin, TitleMixin, CommentedDetailView):
    context_object_name = 'problem'
    template_name = 'problem/problem.html'
    nav_tag = 'problem'

    def get_comment_page(self):
        return 'p:%s' % self.object.code

    def get_context_data(self, **kwargs):
        context = super(ProblemDetail, self).get_context_data(**kwargs)
        user = self.request.user
        authed = user.is_authenticated
        context['has_submissions'] = authed and Submission.objects.filter(user=user.profile,
                                                                          problem=self.object).exists()
        contest_problem = (None if not authed or user.profile.current_contest is None else
                           get_contest_problem(self.object, user.profile))
        context['contest_problem'] = contest_problem
        if contest_problem:
            clarifications = self.object.clarifications
            context['has_clarifications'] = clarifications.count() > 0
            context['clarifications'] = clarifications.order_by('-date')
            context['submission_limit'] = contest_problem.max_submissions
            if contest_problem.max_submissions:
                context['submissions_left'] = max(contest_problem.max_submissions -
                                                  get_contest_submission_count(self.object, user.profile,
                                                                               user.profile.current_contest.virtual), 0)
            num_solution = self.contest.limit_solution
            num_solution -= PublicSolution.objects.filter(author=user.profile, problem=self.object,
                                                          contest=self.contest).count()
            context['can_add_solution'] = num_solution > 0
            context['num_solution'] = num_solution

        context['available_judges'] = Judge.objects.filter(online=True, problems=self.object)
        context['show_languages'] = self.object.allowed_languages.count() != Language.objects.count()
        context['has_pdf_render'] = HAS_PDF
        context['completed_problem_ids'] = self.get_completed_problems()
        context['attempted_problems'] = self.get_attempted_problems()

        can_edit = self.object.is_editable_by(user)
        context['can_edit_problem'] = can_edit
        if user.is_authenticated:
            tickets = self.object.tickets
            if not can_edit:
                tickets = tickets.filter(own_ticket_filter(user.profile.id))
            context['has_tickets'] = tickets.exists()
            context['num_open_tickets'] = tickets.filter(is_open=True).values('id').distinct().count()

        try:
            context['editorial'] = Solution.objects.get(problem=self.object)
        except ObjectDoesNotExist:
            pass
        try:
            translation = self.object.translations.get(language=self.request.LANGUAGE_CODE)
        except ProblemTranslation.DoesNotExist:
            context['title'] = self.object.name
            context['language'] = settings.LANGUAGE_CODE
            context['description'] = self.object.description
            context['translated'] = False
        else:
            context['title'] = translation.name
            context['language'] = self.request.LANGUAGE_CODE
            context['description'] = translation.description
            context['translated'] = True

        if not self.object.og_image or not self.object.summary:
            metadata = generate_opengraph('generated-meta-problem:%s:%d' % (context['language'], self.object.id),
                                          context['description'], 'problem')
        context['meta_description'] = self.object.summary or metadata[0]
        context['og_image'] = self.object.og_image or metadata[1]
        return context


class LatexError(Exception):
    pass


class ProblemPdfView(LoginRequiredMixin, ProblemMixin, SingleObjectMixin, View):
    logger = logging.getLogger('judge.problem.pdf')
    languages = set(map(itemgetter(0), settings.LANGUAGES))

    def get(self, request, *args, **kwargs):
        if not HAS_PDF:
            raise Http404()

        language = kwargs.get('language', self.request.LANGUAGE_CODE)
        if language not in self.languages:
            raise Http404()

        problem = self.get_object()
        try:
            trans = problem.translations.get(language=language)
        except ProblemTranslation.DoesNotExist:
            trans = None

        cache = os.path.join(settings.PDF_PROBLEM_CACHE, '%s.%s.pdf' % (problem.code, language))

        if not os.path.exists(cache):
            self.logger.info('Rendering: %s.%s.pdf', problem.code, language)
            with DefaultPdfMaker() as maker, translation.override(language):
                problem_name = problem.name if trans is None else trans.name
                maker.html = get_template('problem/raw.html').render({
                    'problem': problem,
                    'problem_name': problem_name,
                    'description': problem.description if trans is None else trans.description,
                    'url': request.build_absolute_uri(),
                    'math_engine': maker.math_engine,
                }).replace('"//', '"https://').replace("'//", "'https://")
                maker.title = problem_name

                assets = ['full_style.css', 'pygment-github.css']
                icons = ['logo.svg']
                if maker.math_engine == 'jax':
                    assets.append('mathjax_config.js')
                for file in assets:
                    maker.load(file, os.path.join(settings.RESOURCES, file))
                for file in icons:
                    maker.load(file, settings.RESOURCES / 'icons' / file)
                maker.make()
                if not maker.success:
                    self.logger.error('Failed to render PDF for %s', problem.code)
                    return HttpResponse(maker.log, status=500, content_type='text/plain')
                shutil.move(maker.pdffile, cache)

        response = HttpResponse()

        if hasattr(settings, 'PDF_PROBLEM_INTERNAL'):
            url_path = '%s/%s.%s.pdf' % (settings.PDF_PROBLEM_INTERNAL, problem.code, language)
        else:
            url_path = None

        add_file_response(request, response, url_path, cache)

        response['Content-Type'] = 'application/pdf'
        response['Content-Disposition'] = 'inline; filename=%s.%s.pdf' % (problem.code, language)
        return response


class ProblemList(QueryStringSortMixin, TitleMixin, SolvedProblemMixin, ListView):
    model = Problem
    title = gettext_lazy('Problems')
    nav_tag = 'problem'
    context_object_name = 'problems'
    template_name = 'problem/list.html'
    paginate_by = 50
    sql_sort = frozenset(('points', 'ac_rate', 'user_count', 'code'))
    manual_sort = frozenset(('name', 'group', 'solved', 'type'))
    all_sorts = sql_sort | manual_sort
    default_desc = frozenset(('points', 'ac_rate', 'user_count'))
    default_sort = 'code'

    def get_paginator(self, queryset, per_page, orphans=0,
                      allow_empty_first_page=True, **kwargs):
        paginator = DiggPaginator(queryset, per_page, body=6, padding=2, orphans=orphans,
                                  allow_empty_first_page=allow_empty_first_page, **kwargs)
        # Get the number of pages and then add in this magic.
        # noinspection PyStatementEffect
        paginator.num_pages

        queryset = queryset.add_i18n_name(self.request.LANGUAGE_CODE)
        sort_key = self.order.lstrip('-')
        if sort_key in self.sql_sort:
            queryset = queryset.order_by(self.order, 'id')
        elif sort_key == 'name':
            queryset = queryset.order_by(self.order.replace('name', 'i18n_name'), 'id')
        elif sort_key == 'group':
            queryset = queryset.order_by(self.order + '__name', 'id')
        elif sort_key == 'solved':
            if self.request.user.is_authenticated:
                profile = self.request.profile
                solved = user_completed_ids(profile)
                attempted = user_attempted_ids(profile)

                def _solved_sort_order(problem):
                    if problem.id in solved:
                        return 1
                    if problem.id in attempted:
                        return 0
                    return -1

                queryset = list(queryset)
                queryset.sort(key=_solved_sort_order, reverse=self.order.startswith('-'))
        elif sort_key == 'type':
            queryset = list(queryset)
            queryset.sort(key=lambda problem: problem.types_list[0] if problem.types_list else '',
                          reverse=self.order.startswith('-'))
        paginator.object_list = queryset
        return paginator

    @cached_property
    def profile(self):
        if not self.request.user.is_authenticated:
            return None
        return self.request.profile

    def get_normal_queryset(self):
        filter = Q(is_public=True) | Q(public_description=True)
        if self.profile is not None:
            filter |= Q(authors=self.profile)
            filter |= Q(curators=self.profile)
            filter |= Q(testers=self.profile)
        queryset = Problem.objects.filter(filter).select_related('group').defer('description', 'summary')
        if not self.request.user.has_perm('see_organization_problem'):
            filter = Q(is_organization_private=False) | Q(public_description=True)
            if self.profile is not None:
                filter |= Q(organizations__in=self.profile.organizations.all())
            queryset = queryset.filter(filter)
        if self.profile is not None and self.hide_solved:
            queryset = queryset.exclude(id__in=Submission.objects.filter(user=self.profile, points=F('problem__points'))
                                        .values_list('problem__id', flat=True))
        queryset = queryset.prefetch_related('types')
        if self.category is not None:
            queryset = queryset.filter(group__id=self.category)
        if self.selected_types:
            queryset = queryset.filter(types__in=self.selected_types)
        if 'search' in self.request.GET:
            self.search_query = query = ' '.join(self.request.GET.getlist('search')).strip()
            if query:
                if settings.ENABLE_FTS and self.full_text:
                    queryset = queryset.search(query, queryset.BOOLEAN).extra(order_by=['-relevance'])
                else:
                    queryset = queryset.filter(
                        Q(code__icontains=query) | Q(name__icontains=query) |
                        Q(translations__name__icontains=query, translations__language=self.request.LANGUAGE_CODE))
        # self.prepoint_queryset = queryset
        # if self.point_start is not None:
        #     queryset = queryset.filter(points__gte=self.point_start)
        # if self.point_end is not None:
        #     queryset = queryset.filter(points__lte=self.point_end)
        return queryset.distinct()

    def get_queryset(self):
        return self.get_normal_queryset()

    def get_context_data(self, **kwargs):
        context = super(ProblemList, self).get_context_data(**kwargs)
        context['hide_solved'] = 0 if self.in_contest else int(self.hide_solved)
        context['full_text'] = 0 if self.in_contest else int(self.full_text)
        context['category'] = self.category
        context['categories'] = ProblemGroup.objects.all()
        context['selected_types'] = self.selected_types
        context['problem_types'] = ProblemType.objects.filter(priority=True)
        context['has_fts'] = settings.ENABLE_FTS
        context['search_query'] = self.search_query
        context['completed_problem_ids'] = self.get_completed_problems()
        context['attempted_problems'] = self.get_attempted_problems()

        context.update(self.get_sort_paginate_context())
        context.update(self.get_sort_context())
        context['hot_problems'] = hot_problems(timedelta(days=1), settings.DMOJ_PROBLEM_HOT_PROBLEM_COUNT)
        # context['point_start'], context['point_end'], context['point_values'] = self.get_noui_slider_points()
        return context

    # def get_noui_slider_points(self):
    #     points = sorted(self.prepoint_queryset.values_list('points', flat=True).distinct())
    #     if not points:
    #         return 0, 0, {}
    #     if len(points) == 1:
    #         return points[0], points[0], {
    #             'min': points[0] - 1,
    #             'max': points[0] + 1,
    #         }

    #     start, end = points[0], points[-1]
    #     if self.point_start is not None:
    #         start = self.point_start
    #     if self.point_end is not None:
    #         end = self.point_end
    #     points_map = {0.0: 'min', 1.0: 'max'}
    #     size = len(points) - 1
    #     return start, end, {points_map.get(i / size, '%.2f%%' % (100 * i / size,)): j for i, j in enumerate(points)}

    def GET_with_session(self, request, key):
        if not request.GET:
            return request.session.get(key, False)
        return request.GET.get(key, None) == '1'

    def setup_problem_list(self, request):
        self.hide_solved = self.GET_with_session(request, 'hide_solved')
        self.full_text = self.GET_with_session(request, 'full_text')

        self.search_query = None
        self.category = None
        self.selected_types = []

        # This actually copies into the instance dictionary...
        self.all_sorts = set(self.all_sorts)

        self.category = safe_int_or_none(request.GET.get('category'))
        if 'type' in request.GET:
            try:
                self.selected_types = list(map(int, request.GET.getlist('type')))
                if not ProblemType.objects.filter(pk__in=self.selected_types, priority=True).exists():
                    raise Http404()
            except ValueError:
                pass
        # self.point_start = safe_float_or_none(request.GET.get('point_start'))
        # self.point_end = safe_float_or_none(request.GET.get('point_end'))

    def get(self, request, *args, **kwargs):
        self.setup_problem_list(request)

        try:
            return super(ProblemList, self).get(request, *args, **kwargs)
        except ProgrammingError as e:
            return generic_message(request, 'FTS syntax error', e.args[1], status=400)

    def post(self, request, *args, **kwargs):
        to_update = ('hide_solved', 'full_text')
        for key in to_update:
            if key in request.GET:
                val = request.GET.get(key) == '1'
                request.session[key] = val
            else:
                request.session.pop(key, None)
        return HttpResponseRedirect(request.get_full_path())


class LanguageTemplateAjax(View):
    def get(self, request, *args, **kwargs):
        try:
            language = get_object_or_404(Language, id=int(request.GET.get('id', 0)))
        except ValueError:
            raise Http404()
        return HttpResponse(language.template, content_type='text/plain')


class RandomProblem(ProblemList):
    def get(self, request, *args, **kwargs):
        self.setup_problem_list(request)
        if self.in_contest:
            raise Http404()

        queryset = self.get_normal_queryset()
        count = queryset.count()
        if not count:
            return HttpResponseRedirect('%s%s%s' % (reverse('problem_list'), request.META['QUERY_STRING'] and '?',
                                                    request.META['QUERY_STRING']))
        return HttpResponseRedirect(queryset[randrange(count)].get_absolute_url())


user_logger = logging.getLogger('judge.user')


class ProblemSubmit(LoginRequiredMixin, ProblemMixin, TitleMixin, SingleObjectFormView):
    template_name = 'problem/submit.html'
    form_class = ProblemSubmitForm

    @cached_property
    def contest_problem(self):
        # return None
        if self.request.profile.current_contest is None:
            return None
        return get_contest_problem(self.object, self.request.profile)

    @cached_property
    def remaining_submission_count(self):
        max_subs = self.contest_problem and self.contest_problem.max_submissions
        if max_subs is None:
            return None
        # When an IE submission is rejudged into a non-IE status, it will count towards the
        # submission limit. We max with 0 to ensure that `remaining_submission_count` returns
        # a non-negative integer, which is required for future checks in this view.
        return max(
            0,
            max_subs - get_contest_submission_count(
                self.object, self.request.profile, self.request.profile.current_contest.virtual,
            ),
        )

    @cached_property
    def default_language(self):
        # If the old submission exists, use its language, otherwise use the user's default language.
        if self.old_submission is not None:
            return self.old_submission.language
        return self.request.profile.language

    def get_content_title(self):
        return mark_safe(
            escape(_('Submit to %s')) % format_html(
                '<a href="{0}">{1}</a>',
                reverse('problem_detail', args=[self.object.code]),
                self.object.translated_name(self.request.LANGUAGE_CODE),
            ),
        )

    def get_title(self):
        return _('Submit to %s') % self.object.translated_name(self.request.LANGUAGE_CODE)

    def get_initial(self):
        initial = {'language': self.default_language}
        if self.old_submission is not None:
            initial['source'] = self.old_submission.source.source
        return initial

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['instance'] = Submission(user=self.request.profile, problem=self.object)

        if self.object.is_editable_by(self.request.user):
            kwargs['judge_choices'] = tuple(
                Judge.objects.filter(online=True, problems=self.object).values_list('name', 'name'),
            )
        else:
            kwargs['judge_choices'] = ()

        return kwargs

    def get_form(self, form_class=None):
        form = super().get_form(form_class)

        if self.request.in_contest and self.request.participation.contest.is_limit_language:
            lang = self.request.participation.contest.limit_language
            form.fields['language'].queryset = (
                self.object.usable_languages.filter(pk=lang.pk).order_by('name', 'key')
                .prefetch_related(Prefetch('runtimeversion_set', RuntimeVersion.objects.order_by('priority')))
            )
        else:
            form.fields['language'].queryset = (
                self.object.usable_languages.order_by('name', 'key')
                .prefetch_related(Prefetch('runtimeversion_set', RuntimeVersion.objects.order_by('priority')))
            )

        form_data = getattr(form, 'cleaned_data', form.initial)
        if 'language' in form_data:
            form.fields['source'].widget.mode = form_data['language'].ace
        form.fields['source'].widget.theme = self.request.profile.ace_theme

        return form

    def get_success_url(self):
        return reverse('submission_status', args=(self.new_submission.id,))

    def form_valid(self, form):
        if (
            not self.request.user.has_perm('judge.spam_submission') and
            Submission.objects.filter(user=self.request.profile, rejudged_date__isnull=True)
                              .exclude(status__in=['D', 'IE', 'CE', 'AB']).count() >= settings.DMOJ_SUBMISSION_LIMIT
        ):
            return HttpResponse('<h1>You submitted too many submissions.</h1>', status=429)
        if not self.object.allowed_languages.filter(id=form.cleaned_data['language'].id).exists():
            raise PermissionDenied()
        if not self.request.user.is_superuser and self.object.banned_users.filter(id=self.request.profile.id).exists():
            return generic_message(self.request, _('Banned from submitting'),
                                   _('You have been declared persona non grata for this problem. '
                                     'You are permanently barred from submitting this problem.'))
        # Must check for zero and not None. None means infinite submissions remaining.
        if self.remaining_submission_count == 0:
            return generic_message(self.request, _('Too many submissions'),
                                   _('You have exceeded the submission limit for this problem.'))

        with transaction.atomic():
            self.new_submission = form.save(commit=False)

            contest_problem = self.contest_problem
            if contest_problem is not None:
                # Use the contest object from current_contest.contest because we already use it
                # in profile.update_contest().
                self.new_submission.contest_object = self.request.profile.current_contest.contest
                if self.request.profile.current_contest.live:
                    self.new_submission.locked_after = self.new_submission.contest_object.locked_after
                self.new_submission.save()
                ContestSubmission(
                    submission=self.new_submission,
                    problem=contest_problem,
                    participation=self.request.profile.current_contest,
                ).save()
            else:
                self.new_submission.save()

            submission_file = form.files.get('submission_file', None)
            submission_json = submission_file
            if submission_file is not None:
                if self.new_submission.language.key == 'SCRATCH':
                    try:
                        archive = zipfile.ZipFile(submission_file.file)
                        submission_json.file = archive.open('project.json')
                        submission_json.name = str(self.new_submission.id) + '.json'
                        submission_file.name = str(self.new_submission.id) + '.sb3'
                    except (zipfile.BadZipFile, KeyError):
                        pass

                source_url = submission_uploader(
                    submission_file=submission_json,
                    problem_code=self.new_submission.problem.code,
                    user_id=self.new_submission.user.user.id,
                )
                origin_url = submission_uploader(
                    submission_file=submission_file,
                    problem_code=self.new_submission.problem.code,
                    user_id=self.new_submission.user.user.id,
                )
                # has_file = True
            else:
                # has_file = False
                source_url = ''
                origin_url = ''

            source = SubmissionSource(
                submission=self.new_submission,
                source=form.cleaned_data['source'] + source_url,
                file=origin_url,
            )
            source.save()

        # Save a query.
        self.new_submission.source = source
        self.new_submission.judge(force_judge=True, judge_id=form.cleaned_data['judge'])

        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['langs'] = Language.objects.all()
        context['no_judges'] = not context['form'].fields['language'].queryset
        context['submission_limit'] = self.contest_problem and self.contest_problem.max_submissions
        context['submissions_left'] = self.remaining_submission_count
        context['ACE_URL'] = settings.ACE_URL
        context['default_lang'] = self.default_language
        return context

    def post(self, request, *args, **kwargs):
        try:
            return super().post(request, *args, **kwargs)
        except Http404:
            # Is this really necessary? This entire post() method could be removed if we don't log this.
            user_logger.info(
                'Naughty user %s wants to submit to %s without permission',
                request.user.username,
                kwargs.get(self.slug_url_kwarg),
            )
            return HttpResponseForbidden('<h1>Do you want me to ban you?</h1>')

    def get(self, request, *args, **kwargs):
        self.object: Problem = self.get_object()
        if not self.object.can_submitted_by(request.user):
            return generic_message(request,
                                   _('Can\'t submit to problem'),
                                   _('You don\'t have the permission to submit this problem.'
                                     ' Please contact admin for permission.'),
                                   status=403)
        return super().get(request, *args, **kwargs)

    def dispatch(self, request, *args, **kwargs):
        submission_id = kwargs.get('submission')
        if submission_id is not None:
            self.old_submission = get_object_or_404(
                Submission.objects.select_related('source', 'language'),
                id=submission_id,
            )
            if not request.user.has_perm('judge.resubmit_other') and self.old_submission.user != request.profile:
                raise PermissionDenied()
        else:
            self.old_submission = None

        if request.in_contest and request.participation.contest.start_time > timezone.now():
            return generic_message(request, _('Contest not ongoing'),
                                   _('You cannot submit now.'), status=403)

        return super().dispatch(request, *args, **kwargs)


class ProblemClone(ProblemMixin, PermissionRequiredMixin, TitleMixin, SingleObjectFormView):
    title = _('Clone Problem')
    template_name = 'problem/clone.html'
    form_class = ProblemCloneForm
    permission_required = 'judge.clone_problem'

    def form_valid(self, form):
        problem = self.object

        languages = problem.allowed_languages.all()
        language_limits = problem.language_limits.all()
        organizations = problem.organizations.all()
        types = problem.types.all()
        old_code = problem.code

        problem.pk = None
        problem.is_public = False
        problem.ac_rate = 0
        problem.user_count = 0
        problem.code = form.cleaned_data['code']
        with revisions.create_revision(atomic=True):
            problem.save()
            problem.authors.add(self.request.profile)
            problem.allowed_languages.set(languages)
            problem.language_limits.set(language_limits)
            problem.organizations.set(organizations)
            problem.types.set(types)
            revisions.set_user(self.request.user)
            revisions.set_comment(_('Cloned problem from %s') % old_code)

        return HttpResponseRedirect(reverse('admin:judge_problem_change', args=(problem.pk,)))


class ProblemCreate(ProblemMixin, PermissionRequiredMixin, TitleMixin, CreateView):
    title = _('Create Problem')
    template_name = 'problem/create.html'
    form_class = ProblemCreateForm
    permission_required = 'judge.add_problem'


class ProblemUpdate(ProblemMixin, PermissionRequiredMixin, TitleMixin, UpdateView):
    title = _('Update Problem')
    template_name = 'problem/create.html'
    form_class = ProblemUpdateForm
    permission_required = 'judge.edit_problem'


class PublicSolutionCreateView(TitleMixin, LoginRequiredMixin, CreateView):
    model = PublicSolution
    template_name = "problem/create_solution.html"
    form_class = CreatePublicSolutionForm

    def post(self, request, *args, **kwargs) -> HttpResponse:
        return super().post(request, *args, **kwargs)

    def get_title(self):
        return "Create solution for %s" % (self.problem.name)

    def dispatch(self, request, *args, **kwargs):
        code = self.kwargs.get('problem', None)
        profile: Profile = self.request.profile
        self.problem: Problem = Problem.objects.get(code=code)
        if profile.current_contest is not None:
            self.contest: Contest = profile.current_contest.contest
            if self.problem not in self.contest.problems.all():
                raise Http404()
            num_solution = PublicSolution.objects.filter(contest=self.contest,
                                                         problem=self.problem, author=profile).count()
            if num_solution >= self.contest.limit_solution:
                raise Http404()

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: CreatePublicSolutionForm):
        user = self.request.user.profile
        ps: PublicSolution = form.save(commit=False)
        ps.author = user
        ps.problem = self.problem
        ps.contest = self.contest
        ps.save()
        return HttpResponseRedirect(reverse('problem_detail', args=(self.problem.code,)))


class PublicSolutionListView(TitleMixin, DiggPaginatorMixin, ListView):
    model = PublicSolution
    template_name = "problem/list_solution.html"
    context_object_name = 'solutions'
    paginate_by = 50

    def get_title(self):
        return "Solution for %s" % (self.problem.name)

    def dispatch(self, request, *args, **kwargs):
        code = self.kwargs.get('problem', None)
        self.problem: Problem = get_object_or_404(Problem, code=code)
        return super().dispatch(request, *args, **kwargs)

    def _get_queryset(self):
        qs = super().get_queryset()
        qs = qs.filter(problem=self.problem)
        return qs

    @cached_property
    def profile(self):
        if not self.request.user.is_authenticated:
            return None
        return self.request.profile

    def get_queryset(self):
        queryset = self._get_queryset()
        if self.profile is None or not self.request.user.is_superuser:
            queryset = queryset.filter(approved=True)
        return queryset


class SolutionMixin(object):
    model = PublicSolution
    context_object_name = 'solution'

    def get_object(self, queryset=None):
        solution = super().get_object(queryset)
        if not solution.is_accessible_by(self.request.user):
            raise Http404()
        return solution

    def no_such_solution(self):
        pk = self.kwargs.get(self.slug_url_kwarg, None)
        return generic_message(self.request, _('No such solution'),
                               _('Could not find a problem with the id "%s".') % pk, status=404)

    def get(self, request, *args, **kwargs):
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            return self.no_such_solution()


class PublicSolutionDetailView(TitleMixin, LoginRequiredMixin, SolutionMixin, CommentedDetailView):
    template_name = "problem/solution.html"

    def get_comment_page(self):
        return 's:%s' % self.object.pk

    def get_content_title(self):
        solution = self.object
        return mark_safe(escape(_('Solution of %(problem)s by %(user)s')) % {
            'problem': format_html('<a href="{0}" class="text-blue-500">{1}</a>',
                                   reverse('problem_detail', args=[solution.problem.code]),
                                   solution.problem.translated_name(self.request.LANGUAGE_CODE)),
            'user': format_html('<a href="{0}" class="text-blue-500">{1}</a>',
                                reverse('user_page', args=[solution.author.user.username]),
                                solution.author.user.username),
        })

    def get_title(self):
        return "Solution of problem %s" % (self.object.problem.code)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if SolutionVote.objects.filter(voter=self.request.user.profile, solution=self.get_object()).exists():
            context['vote'] = SolutionVote.objects.filter(voter=self.request.user.profile,
                                                          solution=self.get_object()).first().score
        else:
            context['vote'] = 0
        return context


@login_required
def vote_solution(request, delta):
    if abs(delta) != 1:
        return HttpResponseBadRequest(_('Messing around, are we?'), content_type='text/plain')

    if request.method != 'POST':
        return HttpResponseForbidden()

    if 'id' not in request.POST or len(request.POST['id']) > 10:
        return HttpResponseBadRequest()

    if not request.user.is_staff and not request.profile.has_any_solves:
        return HttpResponseBadRequest(_('You must solve at least one problem before you can vote.'),
                                      content_type='text/plain')

    if request.profile.mute:
        return HttpResponseBadRequest(_('Your part is silent, little toad.'), content_type='text/plain')
    try:
        solution_id = int(request.POST['id'])
    except ValueError:
        return HttpResponseBadRequest()
    else:
        if not PublicSolution.objects.filter(id=solution_id).exists():
            raise Http404()

    vote: SolutionVote = SolutionVote.objects.get_or_create(voter=request.profile, solution_id=solution_id)[0]
    if abs(vote.score + delta) > 1:
        return HttpResponseBadRequest(_('You already voted.'), content_type='text/plain')
    PublicSolution.objects.filter(id=solution_id).update(score=F('score') + delta)
    vote.score += delta
    vote.save()
    return HttpResponse('success', content_type='text/plain')


def upvote_solution(request):
    return vote_solution(request, 1)


def downvote_solution(request):
    return vote_solution(request, -1)
