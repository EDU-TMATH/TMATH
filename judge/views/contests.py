import json
import logging
import os
import shutil
from calendar import SUNDAY, Calendar
from collections import defaultdict, namedtuple
from datetime import date, datetime, time, timedelta
from functools import partial
from itertools import chain
from operator import attrgetter, itemgetter

import pandas
from django import forms
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import (LoginRequiredMixin,
                                        PermissionRequiredMixin)
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
from django.db import IntegrityError
from django.db.models import (Case, Count, F, FloatField, IntegerField, Max,
                              Min, Q, Value, When)
from django.db.models.expressions import CombinedExpression
from django.http import (Http404, HttpResponse, HttpResponseBadRequest,
                         HttpResponseRedirect)
from django.shortcuts import get_object_or_404, render
from django.template.defaultfilters import date as date_filter
from django.template.loader import get_template
from django.urls import reverse
from django.utils import timezone, translation
from django.utils.functional import cached_property
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.timezone import make_aware
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.decorators.http import require_POST
from django.views.generic import ListView, TemplateView, View
from django.views.generic.detail import (BaseDetailView, DetailView,
                                         SingleObjectMixin)
from reversion import revisions

from judge.comments import CommentedDetailView
from judge.forms import ContestCloneForm
from judge.models import (Contest, ContestMoss, ContestParticipation,
                          ContestProblem, ContestTag, Profile, Submission)
from judge.models.contest import SampleContest
from judge.models.problem import ProblemTranslation
from judge.models.profile import Organization
from judge.pdf_problems import HAS_PDF, DefaultPdfMaker
from judge.tasks import run_moss
from judge.utils.celery import redirect_to_task_status
from judge.utils.opengraph import generate_opengraph
from judge.utils.problems import _get_result_data
from judge.utils.ranker import ranker
from judge.utils.stats import get_bar_chart, get_pie_chart
from judge.utils.views import (DiggPaginatorMixin, QueryStringSortMixin,
                               SingleObjectFormView, TitleMixin,
                               add_file_response, generic_message)

__all__ = ['ContestList', 'ContestDetail', 'ContestRanking', 'ContestJoin', 'contestLeave', 'ContestCalendar',
           'ContestClone', 'ContestStats', 'ContestMossView', 'ContestMossDelete', 'contest_ranking_ajax',
           'ContestParticipationList', 'ContestParticipationDisqualify', 'get_contest_ranking_list',
           'base_contest_ranking_list', 'exportExcel']


def _find_contest(request, key, private_check=True):
    try:
        contest = Contest.objects.get(key=key)
        if private_check and not contest.is_accessible_by(request.user):
            raise ObjectDoesNotExist()
    except ObjectDoesNotExist:
        return generic_message(request, _('No such contest'),
                               _('Could not find a contest with the key "%s".') % key, status=404), False
    return contest, True


class ContestListMixin(object):
    def get_queryset(self):
        # queryset = Contest.objects.filter(is_visible=True)
        # if not self.request.user.is_authenticated:
        #     return queryset.filter(is_private=False)
        # if not self.request.user.is_superuser:
        #     return queryset.filter(Q(is_private=False) |
        #                            Q(is_private=True, private_contestants=self.request.user.profile))
        # return Contest.objects.all()
        return Contest.get_visible_contests(self.request.user)


class ContestList(QueryStringSortMixin, DiggPaginatorMixin, TitleMixin, ContestListMixin, ListView):
    model = Contest
    paginate_by = 20
    template_name = 'contest/list.html'
    title = gettext_lazy('Contests')
    nav_tag = 'contest'
    context_object_name = 'past_contests'
    all_sorts = frozenset(('name', 'user_count', 'start_time'))
    default_desc = frozenset(('name', 'user_count'))
    default_sort = '-start_time'

    @cached_property
    def _now(self):
        return timezone.now()

    def _get_queryset(self):
        query = super().get_queryset().prefetch_related(
            'tags',
            'organizations',
            'authors',
            'curators',
            'testers',
        )
        if self.selected_org:
            query = query.exclude(is_private=True).filter(organizations=self.selected_org)
        # if not self.request.user.is_superuser:
        #     filter = Q(is_private=True)
        #     if self.request.user.is_authenticated:
        #         filter &= ~Q(private_contestants=self.request.profile)  # Exclude private contests
        #     query = query.exclude(filter)
        return query

    def get_queryset(self):
        return self._get_queryset().order_by(self.order, 'key').filter(end_time__lt=self._now)

    def get_context_data(self, **kwargs):
        context = super(ContestList, self).get_context_data(**kwargs)
        present, active, future = [], [], []
        for contest in self._get_queryset().exclude(end_time__lt=self._now):
            if (contest.pre_time and contest.pre_time > self._now) or \
               (not contest.pre_time and contest.start_time > self._now):
                future.append(contest)
            else:
                present.append(contest)

        if self.request.user.is_authenticated:
            for participation in ContestParticipation.objects.filter(virtual=0, user=self.request.profile,
                                                                     contest_id__in=present) \
                    .select_related('contest') \
                    .prefetch_related('contest__authors', 'contest__curators', 'contest__testers') \
                    .annotate(key=F('contest__key')):
                if not participation.ended:
                    active.append(participation)
                    present.remove(participation.contest)

        active.sort(key=attrgetter('end_time', 'key'))
        present.sort(key=attrgetter('end_time', 'key'))
        future.sort(key=attrgetter('start_time'))
        context['active_participations'] = active
        context['current_contests'] = present
        context['future_contests'] = future
        context['list_organizations'] = Organization.objects.all()
        if self.selected_org:
            context['organizations'] = int(self.selected_org)
        context['now'] = self._now
        context['first_page_href'] = '.'
        context['page_suffix'] = '#past-contests'
        context.update(self.get_sort_context())
        context.update(self.get_sort_paginate_context())
        return context

    def setup_contest_list(self, request):
        self.selected_org = None

        # This actually copies into the instance dictionary...
        self.all_sorts = set(self.all_sorts)
        if 'organizations' in request.GET:
            try:
                self.selected_org = request.GET.get('organizations')
            except ValueError:
                pass

    def get(self, request, *args, **kwargs):
        self.setup_contest_list(request)
        return super().get(request, *args, **kwargs)


class PrivateContestError(Exception):
    def __init__(self, name, is_private, is_organization_private, orgs):
        self.name = name
        self.is_private = is_private
        self.is_organization_private = is_organization_private
        self.orgs = orgs


class ContestMixin(object):
    context_object_name = 'contest'
    model = Contest
    slug_field = 'key'
    slug_url_kwarg = 'contest'

    @cached_property
    def is_editor(self):
        if not self.request.user.is_authenticated:
            return False
        return self.request.profile.id in self.object.editor_ids

    @cached_property
    def is_tester(self):
        if not self.request.user.is_authenticated:
            return False
        return self.request.profile.id in self.object.tester_ids

    @cached_property
    def can_edit(self):
        return self.object.is_editable_by(self.request.user)

    def get_context_data(self, **kwargs):
        context = super(ContestMixin, self).get_context_data(**kwargs)
        if self.request.user.is_authenticated:
            try:
                context['live_participation'] = (
                    self.request.profile.contest_history.get(
                        contest=self.object,
                        virtual=ContestParticipation.LIVE,
                    )
                )
            except ContestParticipation.DoesNotExist:
                context['live_participation'] = None
                context['has_joined'] = False
            else:
                context['has_joined'] = True
        else:
            context['live_participation'] = None
            context['has_joined'] = False

        context['now'] = timezone.now()
        context['is_editor'] = self.is_editor
        context['is_tester'] = self.is_tester
        context['can_edit'] = self.can_edit

        if not self.object.og_image or not self.object.summary:
            metadata = generate_opengraph('generated-meta-contest:%d' % self.object.id,
                                          self.object.description, 'contest')
        context['meta_description'] = self.object.summary or metadata[0]
        context['og_image'] = self.object.og_image or metadata[1]
        context['has_moss_api_key'] = settings.MOSS_API_KEY is not None
        context['logo_override_image'] = self.object.logo_override_image
        if not context['logo_override_image'] and self.object.organizations.count() == 1:
            context['logo_override_image'] = self.object.organizations.first().logo_override_image

        return context

    def get_object(self, queryset=None):
        contest = super(ContestMixin, self).get_object(queryset)

        profile = self.request.profile
        if (profile is not None and
                ContestParticipation.objects.filter(id=profile.current_contest_id, contest_id=contest.id).exists()):
            return contest
        if contest.is_accessible_by(self.request.user):
            return contest
        try:
            contest.access_check(self.request.user)
        except Contest.PrivateContest:
            raise PrivateContestError(contest.name, contest.is_private, contest.is_organization_private,
                                      contest.organizations.all())
        except Contest.Inaccessible:
            raise Http404()
        else:
            return contest

    def dispatch(self, request, *args, **kwargs):
        try:
            return super(ContestMixin, self).dispatch(request, *args, **kwargs)
        except Http404:
            key = kwargs.get(self.slug_url_kwarg, None)
            if key:
                return generic_message(request, _('No such contest'),
                                       _('Could not find a contest with the key "%s".') % key)
            else:
                return generic_message(request, _('No such contest'),
                                       _('Could not find such contest.'))
        except PrivateContestError as e:
            return render(request, 'contest/private.html', {
                'error': e, 'title': _('Access to contest "%s" denied') % e.name,
            }, status=403)


class ContestDetail(ContestMixin, TitleMixin, CommentedDetailView):
    template_name = 'contest/contest.html'

    def get_comment_page(self):
        return 'c:%s' % self.object.key

    def get_title(self):
        if self.object.is_joinable_by(self.request.user):
            return self.object.full_name
        return self.object.name

    def get_context_data(self, **kwargs):
        context = super(ContestDetail, self).get_context_data(**kwargs)
        context['contest_problems'] = ContestProblem.objects.filter(contest=self.object) \
            .order_by('order').defer('problem__description')
        return context


class ContestClone(ContestMixin, PermissionRequiredMixin, TitleMixin, SingleObjectFormView):
    title = _('Clone Contest')
    template_name = 'contest/clone.html'
    form_class = ContestCloneForm
    permission_required = 'judge.clone_contest'

    def form_valid(self, form):
        contest = self.object

        tags = contest.tags.all()
        organizations = contest.organizations.all()
        private_contestants = contest.private_contestants.all()
        view_contest_scoreboard = contest.view_contest_scoreboard.all()
        contest_problems = list(contest.contest_problems.all())
        old_key = contest.key

        contest.pk = None
        contest.is_visible = False
        contest.user_count = 0
        contest.locked_after = None
        contest.key = form.cleaned_data['key']
        with revisions.create_revision(atomic=True):
            contest.save()
            contest.tags.set(tags)
            contest.organizations.set(organizations)
            contest.private_contestants.set(private_contestants)
            contest.view_contest_scoreboard.set(view_contest_scoreboard)
            contest.authors.add(self.request.profile)

            for problem in contest_problems:
                problem.contest = contest
                problem.pk = None
            ContestProblem.objects.bulk_create(contest_problems)

            revisions.set_user(self.request.user)
            revisions.set_comment(_('Cloned contest from %s') % old_key)

        return HttpResponseRedirect(reverse('admin:judge_contest_change', args=(contest.id,)))


class ContestAccessDenied(Exception):
    pass


class ContestAccessCodeForm(forms.Form):
    access_code = forms.CharField(max_length=255)

    def __init__(self, *args, **kwargs):
        super(ContestAccessCodeForm, self).__init__(*args, **kwargs)
        self.fields['access_code'].widget.attrs.update({'autocomplete': 'off'})


class ContestJoin(LoginRequiredMixin, ContestMixin, BaseDetailView):
    def get(self, request, *args, **kwargs):
        self.object = self.get_object()
        return self.ask_for_access_code()

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        try:
            return self.join_contest(request)
        except ContestAccessDenied:
            if request.POST.get('access_code'):
                return self.ask_for_access_code(ContestAccessCodeForm(request.POST))
            else:
                return HttpResponseRedirect(request.path)

    def join_contest(self, request, access_code=None):
        contest = self.object

        if not contest.can_join and not (self.is_editor or self.is_tester):
            return generic_message(request, _('Contest not ongoing'),
                                   _('"%s" is not currently ongoing.') % contest.name)

        profile = request.profile
        if profile.current_contest is not None:
            return generic_message(request, _('Already in contest'),
                                   _('You are already in a contest: "%s".') % profile.current_contest.contest.name)

        if not request.user.is_superuser and contest.banned_users.filter(id=profile.id).exists():
            return generic_message(request, _('Banned from joining'),
                                   _('You have been declared persona non grata for this contest. '
                                     'You are permanently barred from joining this contest.'))

        requires_access_code = (not self.can_edit and contest.access_code and access_code != contest.access_code)
        if contest.ended:
            if requires_access_code:
                raise ContestAccessDenied()

            while True:
                virtual_id = max((ContestParticipation.objects.filter(contest=contest, user=profile)
                                  .aggregate(virtual_id=Max('virtual'))['virtual_id'] or 0) + 1, 1)
                try:
                    participation = ContestParticipation.objects.create(
                        contest=contest, user=profile, virtual=virtual_id,
                        real_start=timezone.now(),
                    )
                # There is obviously a race condition here, so we keep trying until we win the race.
                except IntegrityError:
                    pass
                else:
                    break
        else:
            SPECTATE = ContestParticipation.SPECTATE
            LIVE = ContestParticipation.LIVE
            if not self.is_editor and requires_access_code:
                raise ContestAccessDenied()
            try:
                participation = ContestParticipation.objects.get(
                    contest=contest, user=profile, virtual=(SPECTATE if self.is_editor or self.is_tester else LIVE),
                )
            except ContestParticipation.DoesNotExist:
                if requires_access_code:
                    raise ContestAccessDenied()

                participation = ContestParticipation.objects.create(
                    contest=contest, user=profile, virtual=(SPECTATE if self.is_editor or self.is_tester else LIVE),
                    real_start=timezone.now(),
                )
            else:
                if participation.ended:
                    participation = ContestParticipation.objects.get_or_create(
                        contest=contest, user=profile, virtual=SPECTATE,
                        defaults={'real_start': timezone.now()},
                    )[0]

        profile.current_contest = participation
        profile.save()
        contest._updating_stats_only = True
        contest.update_user_count()
        return HttpResponseRedirect(reverse('contest_problem_list', args=(contest.key,)))

    def ask_for_access_code(self, form=None):
        contest = self.object
        wrong_code = False
        if form:
            if form.is_valid():
                if form.cleaned_data['access_code'] == contest.access_code:
                    return self.join_contest(self.request, form.cleaned_data['access_code'])
                wrong_code = True
        else:
            form = ContestAccessCodeForm()
        return render(self.request, 'contest/access_code.html', {
            'form': form, 'wrong_code': wrong_code,
            'title': _('Enter access code for "%s"') % contest.name,
        })


@login_required
@require_POST
def contestLeave(request, contest):
    profile = request.profile
    if profile.current_contest is None or profile.current_contest.contest.key != contest:
        return generic_message(request, _('No such contest'),
                               _('You are not in contest "%s".') % contest, 404)

    contest = Contest.objects.get(key=contest)
    if not contest.forbidden_leave:
        profile.remove_contest()
    else:
        return generic_message(request, _('Contest is forbidden to leave'),
                               _('You are not allowed to leave contest "%s" at this time.') % contest, 403)
    return HttpResponseRedirect(reverse('contest_view', args=(contest.key,)))


class ContestLeave(LoginRequiredMixin, ContestMixin, DetailView):
    def post(self, request, *args, **kwargs):
        contest = self.get_object()

        profile = request.profile
        if profile.current_contest is None or profile.current_contest.contest_id != contest.id:
            return generic_message(request, _('No such contest'),
                                   _('You are not in contest "%s".') % contest.key, 404)

        profile.remove_contest()
        return HttpResponseRedirect(reverse('contest_view', args=(contest.key,)))


ContestDay = namedtuple('ContestDay', 'date weekday is_pad is_today starts ends oneday')


class ContestCalendar(TitleMixin, ContestListMixin, TemplateView):
    firstweekday = SUNDAY
    weekday_classes = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
    template_name = 'contest/calendar.html'

    def get(self, request, *args, **kwargs):
        try:
            self.year = int(kwargs['year'])
            self.month = int(kwargs['month'])
        except (KeyError, ValueError):
            raise ImproperlyConfigured(_('ContestCalendar requires integer year and month'))
        self.today = timezone.now().date()
        return self.render()

    def render(self):
        context = self.get_context_data()
        return self.render_to_response(context)

    def get_contest_data(self, start, end):
        end += timedelta(days=1)
        contests = self.get_queryset().filter(Q(start_time__gte=start, start_time__lt=end) |
                                              Q(end_time__gte=start, end_time__lt=end))
        starts, ends, oneday = (defaultdict(list) for i in range(3))
        for contest in contests:
            start_date = timezone.localtime(contest.start_time).date()
            end_date = timezone.localtime(contest.end_time - timedelta(seconds=1)).date()
            if start_date == end_date:
                oneday[start_date].append(contest)
            else:
                starts[start_date].append(contest)
                ends[end_date].append(contest)
        return starts, ends, oneday

    def get_table(self):
        calendar = Calendar(self.firstweekday).monthdatescalendar(self.year, self.month)
        starts, ends, oneday = self.get_contest_data(make_aware(datetime.combine(calendar[0][0], time.min)),
                                                     make_aware(datetime.combine(calendar[-1][-1], time.min)))
        return [[ContestDay(
            date=date, weekday=self.weekday_classes[weekday], is_pad=date.month != self.month,
            is_today=date == self.today, starts=starts[date], ends=ends[date], oneday=oneday[date],
        ) for weekday, date in enumerate(week)] for week in calendar]

    def get_context_data(self, **kwargs):
        context = super(ContestCalendar, self).get_context_data(**kwargs)

        try:
            month = date(self.year, self.month, 1)
        except ValueError:
            raise Http404()
        else:
            context['title'] = _('Contests in %(month)s') % {'month': date_filter(month, _("F Y"))}

        dates = Contest.objects.aggregate(min=Min('start_time'), max=Max('end_time'))
        min_month = (self.today.year, self.today.month)
        if dates['min'] is not None:
            min_month = dates['min'].year, dates['min'].month
        max_month = (self.today.year, self.today.month)
        if dates['max'] is not None:
            max_month = max((dates['max'].year, dates['max'].month), (self.today.year, self.today.month))

        month = (self.year, self.month)
        if month < min_month or month > max_month:
            # 404 is valid because it merely declares the lack of existence, without any reason
            raise Http404()

        context['now'] = timezone.now()
        context['calendar'] = self.get_table()
        context['curr_month'] = date(self.year, self.month, 1)

        if month > min_month:
            context['prev_month'] = date(self.year - (self.month == 1), 12 if self.month == 1 else self.month - 1, 1)
        else:
            context['prev_month'] = None

        if month < max_month:
            context['next_month'] = date(self.year + (self.month == 12), 1 if self.month == 12 else self.month + 1, 1)
        else:
            context['next_month'] = None
        return context


class CachedContestCalendar(ContestCalendar):
    def render(self):
        key = 'contest_cal:%d:%d' % (self.year, self.month)
        cached = cache.get(key)
        if cached is not None:
            return HttpResponse(cached)
        response = super(CachedContestCalendar, self).render()
        response.render()
        cached.set(key, response.content)
        return response


class ContestStats(TitleMixin, ContestMixin, DetailView):
    template_name = 'contest/stats.html'

    def get_title(self):
        return _('%s Statistics') % self.object.name

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        if not (self.object.ended or self.can_edit):
            raise Http404()

        queryset = Submission.objects.filter(contest_object=self.object)

        ac_count = Count(Case(When(result='AC', then=Value(1)), output_field=IntegerField()))
        ac_rate = CombinedExpression(ac_count / Count('problem'), '*', Value(100.0), output_field=FloatField())

        status_count_queryset = list(
            queryset.values('problem__code', 'result').annotate(count=Count('result'))
                    .values_list('problem__code', 'result', 'count'),
        )
        labels, codes = [], []
        contest_problems = self.object.contest_problems.order_by('order').values_list('problem__name', 'problem__code')
        if contest_problems:
            labels, codes = zip(*contest_problems)
        num_problems = len(labels)
        status_counts = [[] for i in range(num_problems)]
        for problem_code, result, count in status_count_queryset:
            if problem_code in codes:
                status_counts[codes.index(problem_code)].append((result, count))

        result_data = defaultdict(partial(list, [0] * num_problems))
        for i in range(num_problems):
            for category in _get_result_data(defaultdict(int, status_counts[i]))['categories']:
                result_data[category['code']][i] = category['count']

        stats = {
            'problem_status_count': {
                'labels': labels,
                'datasets': [
                    {
                        'label': name,
                        'backgroundColor': settings.DMOJ_STATS_SUBMISSION_RESULT_COLORS[name],
                        'data': data,
                    }
                    for name, data in result_data.items()
                ],
            },
            'problem_ac_rate': get_bar_chart(
                queryset.values('contest__problem__order', 'problem__name').annotate(ac_rate=ac_rate)
                        .order_by('contest__problem__order').values_list('problem__name', 'ac_rate'),
            ),
            'language_count': get_pie_chart(
                queryset.values('language__name').annotate(count=Count('language__name'))
                        .filter(count__gt=0).order_by('-count').values_list('language__name', 'count'),
            ),
            'language_ac_rate': get_bar_chart(
                queryset.values('language__name').annotate(ac_rate=ac_rate)
                        .filter(ac_rate__gt=0).values_list('language__name', 'ac_rate'),
            ),
        }

        context['stats'] = mark_safe(json.dumps(stats))

        return context


ContestRankingProfile = namedtuple(
    'ContestRankingProfile',
    'id user css_class username points cumtime tiebreaker organization participation '
    'participation_rating problem_cells result_cell',
)

BestSolutionData = namedtuple('BestSolutionData', 'code points time state is_pretested')


def make_contest_ranking_profile(contest, participation, contest_problems):
    def display_user_problem(contest_problem):
        # When the contest format is changed, `format_data` might be invalid.
        # This will cause `display_user_problem` to error, so we display '???' instead.
        try:
            return contest.format.display_user_problem(participation, contest_problem)
        except (KeyError, TypeError, ValueError):
            return {'has_data': False}

    user = participation.user
    return ContestRankingProfile(
        id=user.id,
        user=user.user,
        css_class=user.css_class,
        username=user.username,
        points=participation.score,
        cumtime=participation.cumtime,
        tiebreaker=participation.tiebreaker,
        organization=user.organization,
        participation_rating=participation.rating.rating if hasattr(participation, 'rating') else None,
        problem_cells=[display_user_problem(contest_problem) for contest_problem in contest_problems],
        result_cell=contest.format.display_participation_result(participation),
        participation=participation,
    )


def base_contest_ranking_list(contest, problems, queryset):
    return [make_contest_ranking_profile(contest, participation, problems) for participation in
            queryset.select_related('user__user', 'rating').defer('user__about', 'user__organizations__about')]


def contest_ranking_list(contest, problems):
    return base_contest_ranking_list(contest, problems, contest.users.filter(virtual=0)
                                     .prefetch_related('user__organizations')
                                     .order_by('is_disqualified', '-score', 'cumtime', 'tiebreaker'))


def get_contest_ranking_list(request, contest, participation=None, ranking_list=contest_ranking_list,
                             show_current_virtual=True, ranker=ranker):
    problems = list(contest.contest_problems.select_related('problem').defer('problem__description').order_by('order'))

    users = ranker(ranking_list(contest, problems), key=attrgetter('points', 'cumtime', 'tiebreaker'))

    if show_current_virtual:
        if participation is None and request.user.is_authenticated:
            participation = request.profile.current_contest
            if participation is None or participation.contest_id != contest.id:
                participation = None
        if participation is not None and participation.virtual:
            users = chain([('-', make_contest_ranking_profile(contest, participation, problems))], users)
    return users, problems


def contest_ranking_ajax(request, contest, participation=None):
    contest, exists = _find_contest(request, contest)
    if not exists:
        return HttpResponseBadRequest('Invalid contest', content_type='text/plain')

    if not contest.can_see_full_scoreboard(request.user):
        raise Http404()

    users, problems = get_contest_ranking_list(request, contest, participation)
    return render(request, 'contest/ranking-table.html', {
        'users': users,
        'problems': problems,
        'contest': contest,
        'has_rating': contest.ratings.exists(),
    })


class ContestRankingBase(LoginRequiredMixin, ContestMixin, TitleMixin, DetailView):
    template_name = 'contest/ranking.html'
    tab = None

    def get_title(self):
        raise NotImplementedError()

    def get_content_title(self):
        return self.object.name

    def get_ranking_list(self):
        raise NotImplementedError()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        if not self.object.can_see_own_scoreboard(self.request.user):
            raise Http404()

        users, problems = self.get_ranking_list()
        context['users'] = users
        context['problems'] = problems
        context['tab'] = self.tab
        return context


class ContestRanking(ContestRankingBase):
    tab = 'ranking'

    def get_title(self):
        return _('%s Rankings') % self.object.name

    def get_ranking_list(self):
        if not self.object.can_see_full_scoreboard(self.request.user):
            queryset = self.object.users.filter(user=self.request.profile, virtual=ContestParticipation.LIVE)
            return get_contest_ranking_list(
                self.request, self.object,
                ranking_list=partial(base_contest_ranking_list, queryset=queryset),
                ranker=lambda users, key: ((_('???'), user) for user in users),
            )

        return get_contest_ranking_list(self.request, self.object)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['has_rating'] = self.object.ratings.exists()
        return context


class ContestParticipationList(ContestRankingBase):
    tab = 'participation'

    def get_title(self):
        if self.profile == self.request.profile:
            return _('Your participation in %s') % self.object.name
        return _("%s's participation in %s") % (self.profile.username, self.object.name)

    def get_ranking_list(self):
        if not self.object.can_see_full_scoreboard(self.request.user) and self.profile != self.request.profile:
            raise Http404()

        queryset = self.object.users.filter(user=self.profile, virtual__gte=0).order_by('-virtual')
        live_link = format_html('<a href="{2}#!{1}">{0}</a>', _('Live'), self.profile.username,
                                reverse('contest_ranking', args=[self.object.key]))

        return get_contest_ranking_list(
            self.request, self.object, show_current_virtual=False,
            ranking_list=partial(base_contest_ranking_list, queryset=queryset),
            ranker=lambda users, key: ((user.participation.virtual or live_link, user) for user in users))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['has_rating'] = False
        context['now'] = timezone.now()
        context['rank_header'] = _('Participation')
        return context

    def get(self, request, *args, **kwargs):
        if 'user' in kwargs:
            self.profile = get_object_or_404(Profile, user__username=kwargs['user'])
        else:
            self.profile = self.request.profile
        return super().get(request, *args, **kwargs)


class ContestParticipationDisqualify(ContestMixin, SingleObjectMixin, View):
    def get_object(self, queryset=None):
        contest = super().get_object(queryset)
        if not contest.is_editable_by(self.request.user):
            raise Http404()
        return contest

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()

        try:
            participation = self.object.users.get(pk=request.POST.get('participation'))
        except ObjectDoesNotExist:
            pass
        else:
            participation.set_disqualified(not participation.is_disqualified)
        return HttpResponseRedirect(reverse('contest_ranking', args=(self.object.key,)))


class ContestMossMixin(ContestMixin, PermissionRequiredMixin):
    permission_required = 'judge.moss_contest'

    def get_object(self, queryset=None):
        contest = super().get_object(queryset)
        if settings.MOSS_API_KEY is None or not contest.is_editable_by(self.request.user):
            raise Http404()
        return contest


class ContestMossView(ContestMossMixin, TitleMixin, DetailView):
    template_name = 'contest/moss.html'

    def get_title(self):
        return _('%s MOSS Results') % self.object.name

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        problems = list(map(attrgetter('problem'), self.object.contest_problems.order_by('order')
                                                              .select_related('problem')))
        languages = list(map(itemgetter(0), ContestMoss.LANG_MAPPING))

        results = ContestMoss.objects.filter(contest=self.object)
        moss_results = defaultdict(list)
        for result in results:
            moss_results[result.problem].append(result)

        for result_list in moss_results.values():
            result_list.sort(key=lambda x: languages.index(x.language))

        context['languages'] = languages
        context['has_results'] = results.exists()
        context['moss_results'] = [(problem, moss_results[problem]) for problem in problems]

        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        status = run_moss.delay(self.object.key)
        return redirect_to_task_status(
            status, message=_('Running MOSS for %s...') % (self.object.name,),
            redirect=reverse('contest_moss', args=(self.object.key,)),
        )


class ContestMossDelete(ContestMossMixin, SingleObjectMixin, View):
    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        ContestMoss.objects.filter(contest=self.object).delete()
        return HttpResponseRedirect(reverse('contest_moss', args=(self.object.key,)))


class ContestTagDetailAjax(DetailView):
    model = ContestTag
    slug_field = slug_url_kwarg = 'name'
    context_object_name = 'tag'
    template_name = 'contest/tag-ajax.html'


class ContestTagDetail(TitleMixin, ContestTagDetailAjax):
    template_name = 'contest/tag.html'

    def get_title(self):
        return _('Contest tag: %s') % self.object.name


# class SampleContestCreateView(TitleMixin, CreateView):
#     title = _('Create Sample Contest')
#     model = SampleContest
#     template_name = "contest/createSampleContest.html"
#     context_object_name = 'contest'
#     slug_url_kwarg: str = 'contest'
#     slug_field: str = 'key'
#     form_class = SampleContestForm


class ContestRawView(ContestMixin, DetailView):
    languages = set(map(itemgetter(0), settings.LANGUAGES))
    template_name: str = 'contest/raw.html'

    def get_context_data(self, **kwargs):
        language = kwargs.get('language', self.request.LANGUAGE_CODE)

        if language not in self.languages:
            raise Http404()

        contest = self.get_object()

        cproblems = contest.contest_problems.order_by('order')

        problems = [c.problem for c in cproblems]

        list_trans = ()

        for problem in problems:
            try:
                trans = problem.translations.get(language=language)
            except ProblemTranslation.DoesNotExist:
                trans = None
            list_trans += ((problem, trans),)
        context = super().get_context_data(**kwargs)
        context['problems'] = [(problem, problem.name if trans is None else
                                trans.name, problem.description if trans is None else
                                trans.description) for problem, trans in list_trans]
        context['url'] = self.request.build_absolute_uri()
        context['math_engine'] = 'jax'
        return context


class ContestPdfView(LoginRequiredMixin, ContestMixin, SingleObjectMixin, View):
    logger = logging.getLogger('judge.problem.pdf')
    languages = set(map(itemgetter(0), settings.LANGUAGES))

    def get(self, request, *args, **kwargs):
        if not HAS_PDF:
            raise Http404()

        language = kwargs.get('language', self.request.LANGUAGE_CODE)

        if language not in self.languages:
            raise Http404()

        contest = self.get_object()

        cproblems = contest.contest_problems.order_by('order')

        problems = [c.problem for c in cproblems]

        list_trans = ()

        for problem in problems:
            try:
                trans = problem.translations.get(language=language)
            except ProblemTranslation.DoesNotExist:
                trans = None
            list_trans += ((problem, trans),)

        cache = os.path.join(settings.PDF_CONTEST_CACHE, '%s.%s.pdf' % (contest.key, language))

        if not os.path.exists(cache):
            self.logger.info('Rendering: %s.%s.pdf', contest.key, language)
            with DefaultPdfMaker() as maker, translation.override(language):
                maker.html = get_template('contest/raw.html').render({
                    'contest': contest,
                    'problems': [(problem, problem.name if trans is None else
                                  trans.name, problem.description if trans is None else
                                  trans.description) for problem, trans in list_trans],
                    'url': request.build_absolute_uri(),
                    'math_engine': maker.math_engine,
                }).replace('"//', '"https://').replace("'//", "'https://")
                maker.title = contest.name

                assets = ['full_style.css', 'pygment-github.css']
                icons = ['logo.svg']
                if maker.math_engine == 'jax':
                    assets.append('mathjax_config.js')
                for file in assets:
                    maker.load(file, settings.RESOURCES / file)
                for file in icons:
                    maker.load(file, settings.RESOURCES / 'icons' / file)
                maker.make()
                if not maker.success:
                    self.logger.error('Failed to render PDF for %s', contest.key)
                    return HttpResponse(maker.log, status=500, content_type='text/plain')
                shutil.move(maker.pdffile, cache)

        response = HttpResponse()

        if hasattr(settings, 'DMOJ_PDF_CONTEST_INTERNAL'):
            url_path = '%s/%s.%s.pdf' % (settings.DMOJ_PDF_CONTEST_INTERNAL, contest.key, language)
        else:
            url_path = None

        add_file_response(request, response, url_path, cache)

        response['Content-Type'] = 'application/pdf'
        response['Content-Disposition'] = 'inline; filename=%s.%s.pdf' % (contest.key, language)
        return response


class SampleContestPDF(SingleObjectMixin, View):
    slug_field: str = 'pk'
    slug_url_kwarg: str = 'pk'
    context_object_name = 'contest'
    model = SampleContest
    logger = logging.getLogger('judge.problem.pdf')
    languages = set(map(itemgetter(0), settings.LANGUAGES))

    def get(self, request, *args, **kwargs):
        if not HAS_PDF:
            raise Http404()

        language = kwargs.get('language', self.request.LANGUAGE_CODE)

        if language not in self.languages:
            raise Http404()

        contest: SampleContest = self.get_object()

        cproblems = contest.contest_problems.all().order_by('order')
        problems = [problem.problem for problem in cproblems]

        list_trans = ()

        for problem in problems:
            try:
                trans = problem.translations.get(language=language)
            except ProblemTranslation.DoesNotExist:
                trans = None
            list_trans += ((problem, trans),)

        cache = os.path.join(settings.PDF_CONTEST_CACHE, '%s.%s.pdf' % (contest.key, language))

        from judge.signals import unlink_if_exists
        if os.path.exists(cache):
            unlink_if_exists(cache)

        if not os.path.exists(cache):
            self.logger.info('Rendering: %s.%s.pdf', contest.key, language)
            with DefaultPdfMaker() as maker, translation.override(language):
                maker.html = get_template('contest/raw.html').render({
                    'contest': contest,
                    'problems': [(problem, problem.name if trans is None else
                                  trans.name, problem.description if trans is None else
                                  trans.description) for problem, trans in list_trans],
                    'url': request.build_absolute_uri(),
                    'math_engine': maker.math_engine,
                }).replace('"//', '"https://').replace("'//", "'https://")
                maker.title = contest.name

                assets = ['style.css', 'pygment-github.css']
                if maker.math_engine == 'jax':
                    assets.append('mathjax_config.js')
                for file in assets:
                    maker.load(file, os.path.join(settings.RESOURCES, file))
                maker.make()
                if not maker.success:
                    self.logger.error('Failed to render PDF for %s', contest.key)
                    return HttpResponse(maker.log, status=500, content_type='text/plain')
                shutil.move(maker.pdffile, cache)

        response = HttpResponse()

        if hasattr(settings, 'DMOJ_PDF_CONTEST_INTERNAL'):
            url_path = '%s/%s.%s.pdf' % (settings.DMOJ_PDF_CONTEST_INTERNAL, contest.key, language)
        else:
            url_path = None

        add_file_response(request, response, url_path, cache)

        response['Content-Type'] = 'application/pdf'
        response['Content-Disposition'] = 'inline; filename=%s.%s.pdf' % (contest.key, language)
        return response


def exportExcel(request, contest):
    contest_object = Contest.objects.get(key=contest)
    response = HttpResponse()
    response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response['Content-Disposition'] = 'attachment; filename=%s_rank.xlsx' % contest_object.key
    keys = ['Rank', 'Fullname', 'Username']
    contestProblems = contest_object.contest_problems.all()
    for contestProblem in contestProblems:
        keys.append(contestProblem.temporary_name)
    keys.append('Total Point')
    data = {key: [] for key in keys}
    participations = ContestParticipation.objects.filter(
        contest=contest_object,
        virtual=ContestParticipation.LIVE,
    ).order_by('-score')
    index = 0
    for participation in participations:
        index += 1
        data['Rank'].append(index)
        data['Fullname'].append(participation.user.name if participation.user.name else participation.user.username)
        data['Username'].append(participation.user.username)
        format_data = participation.format_data or {}
        for contestProblem in contestProblems:
            result = format_data.get(str(contestProblem.id))
            if result:
                point = result['points']
                data[contestProblem.temporary_name].append(str(point))
            else:
                data[contestProblem.temporary_name].append('---')
        data['Total Point'].append(str(participation.score))

    df = pandas.DataFrame(data)

    with pandas.ExcelWriter(response, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Sheet1', index=False)

    return response


class ContestManageView(ContestMixin, TitleMixin, DetailView):
    template_name = 'contest/manage.html'
    tab = 'manage'

    def get_title(self):
        return _('Contest Management')
