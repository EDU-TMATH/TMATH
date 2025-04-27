import json

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import Http404, HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.generic import ListView

from judge.models import Contest, Language, Problem, Profile, Submission
from judge.models.contest import ContestProblem
from judge.utils.infinite_paginator import InfinitePaginationMixin
from judge.utils.problems import (get_result_data, user_completed_ids,
                                  user_editable_ids, user_tester_ids)
from judge.utils.raw_sql import use_straight_join
from judge.utils.views import DiggPaginatorMixin, TitleMixin


def submission_related(queryset):
    return queryset.select_related('user__user', 'problem', 'language') \
        .only('id', 'user__user__username', 'user__display_rank', 'user__rating', 'problem__name',
              'problem__code', 'problem__is_public', 'language__short_name', 'language__key', 'date', 'time', 'memory',
              'points', 'result', 'status', 'case_points', 'case_total', 'current_testcase', 'contest_object',
              'locked_after', 'problem__submission_source_visibility_mode') \
        .prefetch_related('contest_object__authors', 'contest_object__curators')


def filter_submissions_by_visible_problems(queryset, user):
    problems = Problem.get_visible_problems(user).distinct().values_list('id', flat=True)
    queryset = queryset.filter(problem_id__in=problems)


class SubmissionsListBase(LoginRequiredMixin, DiggPaginatorMixin, TitleMixin, ListView):
    model = Submission
    paginate_by = 50
    show_problem = True
    title = gettext_lazy('All submissions')
    content_title = gettext_lazy('All submissions')
    tab = 'all_submissions_list'
    template_name = 'submission/list.html'
    context_object_name = 'submissions'
    first_page_href = None

    def get_result_data(self):
        result = self._get_result_data()
        for category in result['categories']:
            category['name'] = _(category['name'])
        return result

    def _get_result_data(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        return get_result_data(queryset.order_by())

    def access_check(self, request):
        pass

    @cached_property
    def in_contest(self):
        return self.request.user.is_authenticated and self.request.profile.current_contest is not None

    @cached_property
    def contest(self):
        key = self.kwargs['contest']
        return Contest.objects.get(key=key)

    def _get_queryset(self):
        queryset = Submission.objects.all()
        use_straight_join(queryset)
        queryset = submission_related(queryset.order_by('-id'))
        queryset = queryset.filter(contest_object=self.contest)
        if not self.contest.can_see_full_scoreboard(self.request.user):
            queryset = queryset.filter(user=self.request.profile)
        if self.selected_languages:
            languages = Language.objects.filter(key__in=self.selected_languages)
            queryset = queryset.filter(language__in=languages)
        if self.selected_statuses and len(self.selected_statuses) > 0:
            queryset = queryset.filter(result__in=self.selected_statuses)

        return queryset

    def get_queryset(self):
        queryset = self._get_queryset()
        return queryset

    def get_my_submissions_page(self):
        return None

    def get_all_submissions_page(self):
        return reverse('all_contest_submissions', args=[self.contest.key])

    def get_searchable_status_codes(self):
        hidden_codes = ['SC']
        if not self.request.user.is_superuser and not self.request.user.is_staff:
            hidden_codes += ['IE']
        return [(key, value) for key, value in Submission.RESULT if key not in hidden_codes]

    def get_context_data(self, **kwargs):
        context = super(SubmissionsListBase, self).get_context_data(**kwargs)
        authenticated = self.request.user.is_authenticated
        context['dynamic_update'] = False
        context['dynamic_contest_id'] = self.in_contest and self.contest.id
        context['show_problem'] = self.show_problem
        context['completed_problem_ids'] = user_completed_ids(self.request.profile) if authenticated else []
        context['editable_problem_ids'] = user_editable_ids(self.request.profile) if authenticated else []
        context['tester_problem_ids'] = user_tester_ids(self.request.profile) if authenticated else []

        context['all_languages'] = Language.objects.all().values_list('key', 'name')
        context['selected_languages'] = self.selected_languages

        context['all_statuses'] = self.get_searchable_status_codes()
        context['selected_statuses'] = self.selected_statuses

        context['results_json'] = mark_safe(json.dumps(self.get_result_data()))
        context['results_colors_json'] = mark_safe(json.dumps(settings.DMOJ_STATS_SUBMISSION_RESULT_COLORS))

        context['page_suffix'] = suffix = ('?' + self.request.GET.urlencode()) if self.request.GET else ''
        context['first_page_href'] = (self.first_page_href or '.') + suffix
        context['my_submissions_link'] = self.get_my_submissions_page()
        context['all_submissions_link'] = self.get_all_submissions_page()
        context['tab'] = self.tab
        return context

    def get(self, request, *args, **kwargs):
        check = self.access_check(request)
        if check is not None:
            return check

        self.selected_languages = set(request.GET.getlist('language_code'))
        self.selected_statuses = set(request.GET.getlist('status'))

        if 'results' in request.GET:
            return JsonResponse(self.get_result_data())

        return super(SubmissionsListBase, self).get(request, *args, **kwargs)


class UserMixin(object):
    def get(self, request, *args, **kwargs):
        if 'user' not in kwargs:
            raise ImproperlyConfigured('Must pass a user')
        self.profile = get_object_or_404(Profile, user__username=kwargs['user'])
        self.username = kwargs['user']
        return super(UserMixin, self).get(request, *args, **kwargs)


class ConditionalUserTabMixin(object):
    @cached_property
    def is_own(self):
        return self.request.user.is_authenticated and self.request.profile == self.profile

    def get_context_data(self, **kwargs):
        context = super(ConditionalUserTabMixin, self).get_context_data(**kwargs)
        if self.is_own:
            context['tab'] = 'my_submissions_tab'
        else:
            context['tab'] = 'user_submissions_tab'
            context['tab_username'] = self.profile.user.username
        return context


class AllUserSubmissions(ConditionalUserTabMixin, UserMixin, SubmissionsListBase):
    def get_queryset(self):
        return super(AllUserSubmissions, self).get_queryset().filter(user_id=self.profile.id)

    def get_title(self):
        if self.is_own:
            return _('All my submissions')
        return _('All submissions by %s') % self.username

    def get_content_title(self):
        if self.is_own:
            return format_html('All my submissions')
        return format_html('All submissions by <a class="content_title" href="{1}">{0}</a>', self.username,
                           reverse('user_page', args=[self.username]))

    def get_my_submissions_page(self):
        if self.request.user.is_authenticated:
            return reverse('all_user_submissions', kwargs={'user': self.request.user.username})

    def get_context_data(self, **kwargs):
        context = super(AllUserSubmissions, self).get_context_data(**kwargs)
        context['dynamic_update'] = context['page_obj'].number == 1
        context['dynamic_user_id'] = self.profile.id
        return context


class ProblemSubmissionsBase(SubmissionsListBase):
    show_problem = False
    dynamic_update = True
    check_contest_in_access_check = True

    def get_queryset(self):
        if self.in_contest and not self.contest.contest_problems.filter(problem_id=self.problem.id).exists():
            raise Http404()
        return super(ProblemSubmissionsBase, self)._get_queryset().filter(problem_id=self.problem.id)

    def get_title(self):
        return _('All submissions for %s') % self.problem_name

    def get_content_title(self):
        return format_html('All submissions for <a class="content_title" href="{1}">{0}</a>', self.problem_name,
                           self.contest_problem.get_absolute_url())

    def access_check_contest(self, request):
        if self.in_contest and not self.contest.can_see_own_scoreboard(request.user):
            raise Http404()

    def access_check(self, request):
        # FIXME: This should be rolled into the `is_accessible_by` check when implementing #1509
        if self.in_contest and request.user.is_authenticated and request.profile.id in self.contest.editor_ids:
            return

        if not self.problem.is_accessible_by(request.user):
            raise Http404()

        if self.check_contest_in_access_check:
            self.access_check_contest(request)

    def get(self, request, *args, **kwargs):
        if 'problem' not in kwargs:
            raise ImproperlyConfigured(_('Must pass a problem'))
        self.contest_problem = get_object_or_404(ContestProblem, contest__key=kwargs['contest'],
                                                 order=kwargs['problem'])
        self.problem = self.contest_problem.problem
        self.problem_name = self.contest_problem.temporary_name
        return super(ProblemSubmissionsBase, self).get(request, *args, **kwargs)

    def get_all_submissions_page(self):
        return reverse('contest_problem_submissions', kwargs={'problem': self.contest_problem.order,
                                                              'contest': self.contest.key})

    def get_context_data(self, **kwargs):
        context = super(ProblemSubmissionsBase, self).get_context_data(**kwargs)
        if self.dynamic_update:
            context['dynamic_update'] = context['page_obj'].number == 1
            context['dynamic_problem_id'] = self.problem.id
        # context['best_submissions_link'] = reverse('ranked_submissions', kwargs={'problem': self.problem.code})
        return context


class ContestProblemSubmissions(ProblemSubmissionsBase):
    def get_my_submissions_page(self):
        if self.request.user.is_authenticated:
            return reverse('user_contest_problem_submissions',
                           kwargs={'problem': self.contest_problem.order, 'contest': self.contest.key,
                                   'user': self.request.user.username})


class UserContestProblemSubmissions(ConditionalUserTabMixin, UserMixin, ContestProblemSubmissions):
    check_contest_in_access_check = False

    def access_check(self, request):
        super().access_check(request)

        if not self.is_own:
            self.access_check_contest(request)

    def get_queryset(self):
        return super().get_queryset().filter(user_id=self.profile.id)

    def get_title(self):
        if self.is_own:
            return _("My submissions for %(problem)s") % {'problem': self.problem_name}
        return _("%(user)s's submissions for %(problem)s") % {'user': self.username, 'problem': self.problem_name}

    def get_content_title(self):
        if self.request.user.is_authenticated and self.request.profile == self.profile:
            return format_html('''My submissions for <a class="content_title" href="{1}">{0}</a>''',
                               self.problem_name, self.contest_problem.get_absolute_url())
        return format_html('''<a class="content_title" href="{1}">
                           {0}</a>'s submissions for <a class="content_title" href="{3}">{2}</a>''',
                           self.username, reverse('user_page', args=[self.username]),
                           self.problem_name, self.contest_problem.get_absolute_url())

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['dynamic_user_id'] = self.profile.id
        return context


def single_submission(request):
    request.no_profile_update = True
    if 'id' not in request.GET or not request.GET['id'].isdigit():
        return HttpResponseBadRequest()
    try:
        show_problem = int(request.GET.get('show_problem', '1'))
    except ValueError:
        return HttpResponseBadRequest()

    authenticated = request.user.is_authenticated
    submission = get_object_or_404(submission_related(Submission.objects.all()), id=int(request.GET['id']))
    if not submission.problem.is_accessible_by(request.user):
        raise Http404()

    return render(request, 'submission/row.html', {
        'submission': submission,
        'completed_problem_ids': user_completed_ids(request.profile) if authenticated else [],
        'editable_problem_ids': user_editable_ids(request.profile) if authenticated else [],
        'tester_problem_ids': user_tester_ids(request.profile) if authenticated else [],
        'show_problem': show_problem,
        'problem_name': show_problem and submission.problem.translated_name(request.LANGUAGE_CODE),
        'profile_id': request.profile.id if authenticated else 0,
    })


class AllSubmissions(InfinitePaginationMixin, SubmissionsListBase):
    stats_update_interval = 3600

    @property
    def use_infinite_pagination(self):
        return not self.in_contest

    def get_my_submissions_page(self):
        if self.request.user.is_authenticated:
            return reverse('all_user_submissions', kwargs={'user': self.request.user.username})

    def get_context_data(self, **kwargs):
        context = super(AllSubmissions, self).get_context_data(**kwargs)
        context['dynamic_update'] = context['page_obj'].number == 1
        context['stats_update_interval'] = self.stats_update_interval
        return context

    def _get_result_data(self, queryset=None):
        if queryset is not None or self.in_contest or self.selected_languages or self.selected_statuses:
            return super(AllSubmissions, self)._get_result_data(queryset)

        key = 'global_submission_result_data'
        result = cache.get(key)
        if result:
            return result
        result = super(AllSubmissions, self)._get_result_data(Submission.objects.all())
        cache.set(key, result, self.stats_update_interval)
        return result


class ForceContestMixin(object):
    @property
    def in_contest(self):
        return True

    @property
    def contest(self):
        return self._contest

    def access_check(self, request):
        super(ForceContestMixin, self).access_check(request)

        if not request.user.has_perm('judge.see_private_contest'):
            if not self.contest.is_visible:
                raise Http404()
            if self.contest.start_time is not None and self.contest.start_time > timezone.now():
                raise Http404()

    def get_problem_number(self, problem):
        return self.contest.contest_problems.select_related('problem').get(problem=problem).order

    def get(self, request, *args, **kwargs):
        if 'contest' not in kwargs:
            raise ImproperlyConfigured(_('Must pass a contest'))
        self._contest = get_object_or_404(Contest, key=kwargs['contest'])
        return super(ForceContestMixin, self).get(request, *args, **kwargs)


class UserAllContestSubmissions(ForceContestMixin, AllUserSubmissions):
    def get_title(self):
        if self.is_own:
            return _('My submissions in %(contest)s') % {'contest': self.contest.name}
        return _("%(user)s's submissions in %(contest)s") % {
            'user': self.username,
            'contest': self.contest.name,
        }

    def access_check(self, request):
        super().access_check(request)
        if not self.contest.users.filter(user_id=self.profile.id).exists():
            raise Http404()
        if not self.is_own and not self.contest.can_see_full_scoreboard(self.request.user):
            raise Http404()

    def get_content_title(self):
        if self.is_own:
            return format_html(_('My submissions in <a class="content_title" href="{1}">{0}</a>'),
                               self.contest.name, reverse("contest_view", args=[self.contest.key]))
        return format_html(_('<a class="content_title" href="{1}">{0}</a>\'s submissions in <a href="{3}">{2}</a>'),
                           self.username, reverse('user_page', args=[self.username]),
                           self.contest.name, reverse('contest_view', args=[self.contest.key]))

    def get_queryset(self):
        queryset = super().get_queryset()
        # FIXME: fix this line of code when #1509 is implemented
        if not self.request.user.is_authenticated or self.request.profile.id not in self.contest.editor_ids:
            filter_submissions_by_visible_problems(queryset, self.request.user)
        return queryset


class UserContestSubmissions(ForceContestMixin, UserContestProblemSubmissions):
    def get_title(self):
        if self.problem.is_accessible_by(self.request.user):
            return "%s's submissions for %s in %s" % (self.username, self.problem_name, self.contest.name)
        return "%s's submissions for problem %s in %s" % (
            self.username, self.get_problem_number(self.problem), self.contest.name)

    def access_check(self, request):
        super(UserContestSubmissions, self).access_check(request)
        if not self.contest.users.filter(user_id=self.profile.id).exists():
            raise Http404()

    def get_content_title(self):
        if self.problem.is_accessible_by(self.request.user):
            return format_html(_('<a href="{1}">{0}</a>\'s submissions for '
                                 '<a href="{3}">{2}</a> in <a href="{5}">{4}</a>'),
                               self.username, reverse('user_page', args=[self.username]),
                               self.problem_name, reverse('problem_detail', args=[self.problem.code]),
                               self.contest.name, reverse('contest_view', args=[self.contest.key]))
        return format_html(_('<a href="{1}">{0}</a>\'s submissions for '
                             'problem {2} in <a href="{4}">{3}</a>'),
                           self.username, reverse('user_page', args=[self.username]),
                           self.get_problem_number(self.problem),
                           self.contest.name, reverse('contest_view', args=[self.contest.key]))
