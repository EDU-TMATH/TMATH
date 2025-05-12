from random import randrange

from django import forms
from django.contrib import admin
from django.core.exceptions import PermissionDenied
from django.db import connection, transaction
from django.db.models import Count, Q, TextField
from django.forms import ModelForm, ModelMultipleChoiceField
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import path, reverse, reverse_lazy
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext
from grappelli.forms import GrappelliSortableHiddenMixin
from reversion.admin import VersionAdmin

from django_ace import AceWidget
from judge.models import (Contest, ContestProblem, ContestSubmission, Problem,
                          Profile, Rating, SampleContest, Submission)
from judge.models.contest import ContestLevel, SampleContestProblem
from judge.tasks import rate_contest
from judge.utils.views import NoBatchDeleteMixin
from judge.widgets import (AdminHeavySelect2MultipleWidget,
                           AdminHeavySelect2Widget, AdminMartorWidget)


class AdminHeavySelect2Widget(AdminHeavySelect2Widget):
    @property
    def is_hidden(self):
        return False


class ContestTagForm(ModelForm):
    contests = ModelMultipleChoiceField(
        label=_('Included contests'),
        queryset=Contest.objects.all(),
        required=False,
        widget=AdminHeavySelect2MultipleWidget(data_view='contest_select2'))


class ContestTagAdmin(admin.ModelAdmin):
    fields = ('name', 'color', 'description')
    list_display = ('name', 'color')
    actions_on_top = True
    actions_on_bottom = True
    search_fields = ['name']
    formfield_overrides = {
        TextField: {'widget': AdminMartorWidget},
    }


class ContestProblemInlineFormSet(forms.BaseInlineFormSet):
    def clean(self):
        super().clean()
        if any(self.errors):
            return
        orders = []
        for form in self.forms:
            if form.cleaned_data:
                order = form.cleaned_data['order']
                if order in orders:
                    raise forms.ValidationError('Please rearrange the problems so that they have unique order values.')
                orders.append(order)


class ContestProblemInline(GrappelliSortableHiddenMixin, admin.TabularInline):
    model = ContestProblem
    verbose_name = _('Problem')
    verbose_name_plural = 'Problems'
    fields = ('problem', 'points', 'partial', 'is_pretested', 'max_submissions', 'limit_point', 'order',
              'rejudge_column')
    readonly_fields = ('rejudge_column',)
    sortable_field_name = 'order'
    autocomplete_fields = [
        'problem',
    ]
    formset = ContestProblemInlineFormSet
    # form = ContestProblemInlineForm

    def rejudge_column(self, obj):
        if obj.id is None:
            return ''
        return format_html('<a class="button rejudge-link" href="{}">Rejudge</a>',
                           reverse('admin:judge_contest_rejudge', args=(obj.contest.id, obj.id)))
    rejudge_column.short_description = ''

    def get_extra(self, request, obj: Contest, **kwargs) -> int:
        extra = 4
        if obj:
            current = obj.problems.count()
            if current > extra:
                return 0
            return extra - current
        return extra

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'problem':
            kwargs['queryset'] = Problem.objects.annotate(case_count=Count('cases')) \
                .filter(case_count__gt=0, approved=True).order_by('-pk')
            # kwargs['queryset'] = Problem.objects.filter(is_public=True)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


class ContestForm(ModelForm):
    def __init__(self, *args, **kwargs):
        super(ContestForm, self).__init__(*args, **kwargs)
        if 'rate_exclude' in self.fields:
            if self.instance and self.instance.id:
                self.fields['rate_exclude'].queryset = \
                    Profile.objects.filter(contest_history__contest=self.instance).distinct()
            else:
                self.fields['rate_exclude'].queryset = Profile.objects.none()
        self.fields['banned_users'].widget.can_add_related = False
        self.fields['view_contest_scoreboard'].widget.can_add_related = False

    def clean(self):
        cleaned_data = super(ContestForm, self).clean()
        cleaned_data['banned_users'].filter(current_contest__contest=self.instance).update(current_contest=None)

        return cleaned_data

    def save(self, commit=True):
        instance = super(ContestForm, self).save(commit=False)
        # if 'rating_ceiling' in self.cleaned_data:
        #     instance.rating_ceiling = self.cleaned_data['rating_ceiling']
        if commit:
            instance.save()
        return instance

    class Meta:
        widgets = {
            'description': AdminMartorWidget(attrs={'data-markdownfy-url': reverse_lazy('contest_preview')}),
        }


class ContestAdmin(NoBatchDeleteMixin, VersionAdmin):
    change_form_template = 'admin/judge/contest/change_form.html'
    change_list_template = 'admin/judge/contest/change_list.html'
    fieldsets = (
        (None, {'fields': ('key', 'name', 'topic', 'authors', 'curators', 'testers')}),
        (_('Settings'), {
            'fields': ('is_visible', 'is_public_contest', 'use_clarifications', 'hide_problem_tags',
                       'hide_problem_authors', 'run_pretests_only', 'locked_after', 'scoreboard_visibility',
                       'points_precision', 'add_solution', 'limit_solution', 'forbidden_words', 'forbidden_leave'),
        }),
        (_('Scheduling'), {'fields': ('start_time', 'end_time', 'time_limit', 'pre_time')}),
        (_('Details'), {
            'fields': ('is_full_markup', 'description', 'og_image', 'logo_override_image', 'tags', 'summary'),
        }),
        (_('Format'), {
            'fields': ('format_name', 'format_config', 'fastio',
                       'is_limit_language', 'limit_language', 'problem_label_script'),
        }),
        (_('Rating'), {'fields': ('is_rated', 'rate_all', 'rating_floor', 'rating_ceiling', 'rate_exclude')}),
        (_('Access'), {'fields': ('access_code', 'is_private', 'private_contestants', 'is_organization_private',
                                  'organizations', 'view_contest_scoreboard')}),
        (_('Justice'), {'fields': ('banned_users',)}),
    )
    list_display = ('key', 'name', 'topic', 'is_visible', 'is_rated', 'locked_after',
                    'start_time', 'end_time', 'time_limit',
                    'user_count', 'show_word')
    search_fields = ('key', 'name', 'topic')
    inlines = [ContestProblemInline]
    autocomplete_fields = [
        'authors',
        'curators',
        'testers',
        'private_contestants',
        'organizations',
        'banned_users',
        'view_contest_scoreboard',
        'tags',
    ]
    actions_on_top = True
    actions_on_bottom = True
    form = ContestForm
    filter_horizontal = ['rate_exclude']
    date_hierarchy = 'start_time'

    def get_actions(self, request):
        actions = super(ContestAdmin, self).get_actions(request)

        if request.user.has_perm('judge.change_contest_visibility') or \
                request.user.has_perm('judge.create_private_contest'):
            for action in ('make_visible', 'make_hidden'):
                actions[action] = self.get_action(action)

        if request.user.has_perm('judge.lock_contest'):
            for action in ('set_locked', 'set_unlocked'):
                actions[action] = self.get_action(action)

        # if request.user.is_superuser:
        #     actions['update_rate'] = self.get_action('update_rate')

        return actions

    def get_queryset(self, request):
        queryset = Contest.objects.all()
        if request.user.has_perm('judge.edit_all_contest'):
            return queryset
        else:
            return queryset.filter(Q(authors=request.profile) | Q(curators=request.profile)).distinct()

    def get_readonly_fields(self, request, obj=None):
        readonly = []
        if not request.user.has_perm('judge.contest_rating'):
            readonly += ['is_rated', 'rate_all', 'rate_exclude']
        if not request.user.has_perm('judge.lock_contest'):
            readonly += ['locked_after']
        if not request.user.has_perm('judge.contest_access_code'):
            readonly += ['access_code']
        if not request.user.has_perm('judge.create_private_contest'):
            readonly += ['is_private', 'private_contestants', 'is_organization_private', 'organizations']
            if not request.user.has_perm('judge.change_contest_visibility'):
                readonly += ['is_visible']
        if not request.user.has_perm('judge.contest_problem_label'):
            readonly += ['problem_label_script']
        if not request.profile.super_admin:
            readonly += ['rating_ceiling']
        return readonly

    def save_model(self, request, obj, form, change):
        # `is_visible` will not appear in `cleaned_data` if user cannot edit it
        if form.cleaned_data.get('is_visible') and not request.user.has_perm('judge.change_contest_visibility'):
            if not form.cleaned_data['is_private'] and not form.cleaned_data['is_organization_private']:
                raise PermissionDenied
            if not request.user.has_perm('judge.create_private_contest'):
                raise PermissionDenied

        super().save_model(request, obj, form, change)
        # We need this flag because `save_related` deals with the inlines, but does not know if we have already rescored
        self._rescored = False
        if form.changed_data and any(f in form.changed_data for f in ('format_config', 'format_name')):
            self._rescore(obj.key)
            self._rescored = True

        if form.changed_data and 'locked_after' in form.changed_data:
            self.set_locked_after(obj, form.cleaned_data['locked_after'])

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        # Only rescored if we did not already do so in `save_model`
        if not self._rescored and any(formset.has_changed() for formset in formsets):
            self._rescore(form.cleaned_data['key'])

    def has_change_permission(self, request, obj=None):
        if not request.user.has_perm('judge.edit_own_contest'):
            return False
        if obj is None:
            return True
        return obj.is_editable_by(request.user)

    def _rescore(self, contest_key):
        from judge.tasks import rescore_contest
        transaction.on_commit(rescore_contest.s(contest_key).delay)

    def make_visible(self, request, queryset):
        if not request.user.has_perm('judge.change_contest_visibility'):
            queryset = queryset.filter(Q(is_private=True) | Q(is_organization_private=True))
        count = queryset.update(is_visible=True)
        self.message_user(request, ngettext('%d contest successfully marked as visible.',
                                            '%d contests successfully marked as visible.',
                                            count) % count)
    make_visible.short_description = _('Mark contests as visible')

    def make_hidden(self, request, queryset):
        if not request.user.has_perm('judge.change_contest_visibility'):
            queryset = queryset.filter(Q(is_private=True) | Q(is_organization_private=True))
        count = queryset.update(is_visible=True)
        self.message_user(request, ngettext('%d contest successfully marked as hidden.',
                                            '%d contests successfully marked as hidden.',
                                            count) % count)
    make_hidden.short_description = _('Mark contests as hidden')

    def set_locked(self, request, queryset):
        for row in queryset:
            self.set_locked_after(row, timezone.now())
        count = queryset.count()
        self.message_user(request, ngettext('%d contest successfully locked.',
                                            '%d contests successfully locked.',
                                            count) % count)
    set_locked.short_description = _('Lock contest submissions')

    def set_unlocked(self, request, queryset):
        for row in queryset:
            self.set_locked_after(row, None)
        count = queryset.count()
        self.message_user(request, ngettext('%d contest successfully unlocked.',
                                            '%d contests successfully unlocked.',
                                            count) % count)
    set_unlocked.short_description = _('Unlock contest submissions')

    def set_locked_after(self, contest, locked_after):
        with transaction.atomic():
            contest.locked_after = locked_after
            contest.save()
            Submission.objects.filter(contest_object=contest,
                                      contest__participation__virtual=0).update(locked_after=locked_after)

    def update_rate(self, request):
        if not request.user.is_superuser:
            raise PermissionDenied()
        with transaction.atomic():
            contests = Contest.objects.filter(is_rated=True)
            for contest in contests:
                contest.update_rate()
        return HttpResponseRedirect(reverse('admin:judge_contest_changelist'))

    def get_urls(self):
        return [
            path('update/rate/', self.update_rate, name='judge_update_rate'),
            path('rate/all/', self.rate_all_view, name='judge_contest_rate_all'),
            path('<int:id>/rate/', self.rate_view, name='judge_contest_rate'),
            path('<int:contest_id>/judge/<int:problem_id>/', self.rejudge_view, name='judge_contest_rejudge'),
            path('<int:id>/export_word', self.export_word, name='export_word'),
        ] + super(ContestAdmin, self).get_urls()

    def export_word(self, request, id):
        import io
        import os

        import pandoc
        from django.conf import settings

        from judge.signals import unlink_if_exists

        contest = get_object_or_404(Contest, id=id)
        problems = ContestProblem.objects.filter(contest=contest).order_by('order')
        file = os.path.join(settings.WORD_CONTEST_CACHE, "contest_{}.docx".format(contest.key))
        if os.path.exists(file):
            unlink_if_exists(file)
        md = "# {}\r\n\r\n".format(contest.name)
        for index, problem in enumerate(problems):
            md += "# Problem %s" % (contest.get_label_for_problem(index)) + "\r\n\r\n"
            md += str(problem.problem.description) + "\r\n\r\n"
            md += "\r\n\r\n"

        md = md.replace('~', '$')
        md = md.replace('##', '## ')
        md = md.replace('](/', '](%s/' % settings.SITE_FULL_URL)
        doc = pandoc.read(source=md, format='markdown')
        pandoc.write(doc=doc, format='docx', file=file)
        # pandoc.write(doc=doc, format='markdown', file="/tmp/%s.md" % (contest.key))
        f = io.open(file, mode='rb')
        response = HttpResponse(
            f.read(),
            content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        )
        response['Content-Disposition'] = 'attachment; filename="contest_%s.docx"' % (contest.key)
        return response

    def rejudge_view(self, request, contest_id, problem_id):
        queryset = ContestSubmission.objects.filter(problem_id=problem_id).select_related('submission')
        for model in queryset:
            model.submission.judge(rejudge=True)

        self.message_user(request, ngettext('%d submission was successfully scheduled for rejudging.',
                                            '%d submissions were successfully scheduled for rejudging.',
                                            len(queryset)) % len(queryset))
        return HttpResponseRedirect(reverse('admin:judge_contest_change', args=(contest_id,)))

    def rate_all_view(self, request):
        if not request.user.has_perm('judge.contest_rating'):
            raise PermissionDenied()
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute('TRUNCATE TABLE `%s`' % Rating._meta.db_table)
            Profile.objects.update(rating=None)
        rate_contest.delay()
        return HttpResponseRedirect(reverse('admin:judge_contest_changelist'))

    def rate_view(self, request, id):
        if not request.user.has_perm('judge.contest_rating'):
            raise PermissionDenied()
        contest = get_object_or_404(Contest, id=id)
        if not contest.is_rated or not contest.ended:
            raise Http404()
        rate_contest.delay(id)
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', reverse('admin:judge_contest_changelist')))

    def get_form(self, request, obj=None, **kwargs):
        form = super(ContestAdmin, self).get_form(request, obj, **kwargs)
        if 'problem_label_script' in form.base_fields:
            # form.base_fields['problem_label_script'] does not exist when the user has only view permission
            # on the model.
            form.base_fields['problem_label_script'].widget = AceWidget('lua', request.profile.ace_theme)

        perms = ('edit_own_contest', 'edit_all_contest')
        form.base_fields['curators'].queryset = Profile.objects.filter(
            Q(user__is_superuser=True) |
            Q(user__groups__permissions__codename__in=perms) |
            Q(user__user_permissions__codename__in=perms),
        ).distinct()
        return form

    def show_word(self, obj):
        styles = 'white-space:nowrap; background-color: blue; padding: 0.5rem; font-weight:600; border-radius: 6px;'
        return format_html('<a href="{0}" style="{2}">{1}</a>',
                           reverse('admin:export_word', kwargs={'id': obj.id}), _('Export word'), styles)

    def get_search_results(self, request, queryset, search_term):
        queryset, use_distinct = super().get_search_results(request, queryset, search_term)
        if 'autocomplete' in request.path and request.GET.get('model_name') == 'curriculumcontest' \
           and request.GET.get('field_name') == 'contest':
            queryset = queryset.filter(is_visible=False).order_by('-pk')
        return queryset, use_distinct


class ProblemInlineForm(ModelForm):
    def has_changed(self) -> bool:
        return True


class ProblemInlineFormset(forms.BaseInlineFormSet):

    def clean(self):
        super().clean()
        level = self.instance.level
        if level is None:
            return
        delete_forms = self.deleted_forms
        form_valid = [form for form in self.forms if form.is_valid() and form not in delete_forms]
        for form in form_valid:
            problem = form.cleaned_data['problem']
            qs = SampleContestProblem.objects.filter(problem=problem, level=level).exclude(contest=self.instance)
            if qs.exists():
                raise forms.ValidationError('Problem %(problem)s appeared in %(contest)s sample contest!' % {
                    'problem': problem,
                    'contest': qs.first().contest.key,
                })

    def save(self, commit: bool = True):
        level = self.instance.level
        instances = super().save(commit=False)
        for obj in self.deleted_objects:
            obj.delete()
        for instance in instances:
            instance.level = level
            instance.save()
        self.save_m2m()


class ProblemInline(GrappelliSortableHiddenMixin, admin.TabularInline):
    model = SampleContestProblem
    verbose_name = _('Problem')
    verbose_name_plural = 'Problems'
    fields = ('order', 'problem', 'points', 'partial', 'is_pretested', 'max_submissions', 'output_prefix_override')
    autocomplete_fields = ['problem']
    formset = ProblemInlineFormset
    form = ProblemInlineForm
    sortable_field_name = 'order'
    extra: int = 0


class SampleContestForm(ModelForm):
    class Meta:
        widgets = {
            'description': AdminMartorWidget(attrs={'data-markdownfy-url': reverse_lazy('contest_preview')}),
        }


class ContestLevelFilter(admin.SimpleListFilter):
    title = parameter_name = 'level'

    def lookups(self, request, model_admin):
        queryset = ContestLevel.objects.values_list('code', flat=True)
        return [(name, name) for name in queryset]

    def queryset(self, request, queryset):
        if self.value() is None:
            return queryset
        return queryset.filter(level__code=self.value())


@admin.register(SampleContest)
class SampleContestAdmin(VersionAdmin):
    fieldsets = (
        (None, {'fields': ('key', 'name')}),
        (_('Settings'), {'fields': ('is_visible', 'use_clarifications', 'hide_problem_tags', 'hide_problem_authors',
                                    'run_pretests_only', 'scoreboard_visibility',
                                    'points_precision', 'level')}),
        (_('Scheduling'), {'fields': ('time_limit', )}),
        (_('Details'), {'fields': ('is_full_markup', 'description', 'logo_override_image', 'tags', 'summary')}),
        (_('Format'), {'fields': ('format_name', 'format_config', 'problem_label_script')}),
    )
    list_display = ('key', 'name', 'get_number_problems', 'level', 'clone_button', 'pdf_button')
    list_filter = (ContestLevelFilter, )
    autocomplete_fields = [
        'tags',
    ]
    search_fields = ('key', 'name')
    inlines = [ProblemInline]
    actions_on_top = True
    actions_on_bottom = True
    form = SampleContestForm

    def get_number_problems(self, obj):
        return obj.contest_problems.count()

    get_number_problems.short_description = 'Problems'

    def get_urls(self):
        return [
            path('<int:id>/clone/', self.clone, name='judge_samplecontest_clone'),
            path('<int:id>/pdf', self.pdf, name='judge_samplecontest_pdf'),
        ] + super().get_urls()

    def pdf(self, request, id):
        # Check samplecontest has existed
        if not SampleContest.objects.filter(id=id).exists():
            raise Http404()
        return HttpResponseRedirect(reverse('sample_contest_pdf', args=(id,)))

    def clone(self, request, id):
        samplecontest = get_object_or_404(SampleContest, id=id)
        user = request.user
        profile = Profile.objects.filter(user=user)
        contest = Contest.objects.create(
            key=str(samplecontest.id) + 'clone' + str(randrange(0, 10000000, 1)),
            name=samplecontest.name,
            description=samplecontest.description,
            time_limit=samplecontest.time_limit,
            start_time=timezone.now(),
            end_time=timezone.now(),
            scoreboard_visibility=samplecontest.scoreboard_visibility,
            use_clarifications=samplecontest.use_clarifications,
            run_pretests_only=samplecontest.run_pretests_only,
            logo_override_image=samplecontest.logo_override_image,
            is_full_markup=samplecontest.is_full_markup,
            format_name=samplecontest.format_name,
            format_config=samplecontest.format_config,
            points_precision=samplecontest.points_precision,
        )
        contest.authors.set(profile)
        contest.save()
        for problem in SampleContestProblem.objects.filter(contest=samplecontest):
            ContestProblem.objects.create(
                contest=contest,
                problem=problem.problem,
                points=problem.points,
                max_submissions=problem.max_submissions,
                is_pretested=problem.is_pretested,
                partial=problem.partial,
                order=problem.order,
            )

        return HttpResponseRedirect(reverse('admin:judge_contest_change', args=(contest.id,)))

    def clone_button(self, obj):
        return format_html('<a class="button rejudge-link" href="{}">Clone</a>',
                           reverse('admin:judge_samplecontest_clone', args=(obj.id,)))

    def pdf_button(self, obj):
        return format_html('<a class="button rejudge-link" href="{}">PDF</a>',
                           reverse('admin:judge_samplecontest_pdf', args=(obj.id,)))


class ContestParticipationAdmin(admin.ModelAdmin):
    fields = ('contest', 'user', 'real_start', 'virtual', 'is_disqualified')
    list_display = ('contest', 'username', 'show_virtual', 'real_start', 'score', 'cumtime', 'tiebreaker')
    actions = ['recalculate_results']
    actions_on_bottom = actions_on_top = True
    search_fields = ('contest__key', 'contest__name', 'user__user__username')
    date_hierarchy = 'real_start'
    autocomplete_fields = ['user', 'contest']

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        last_record = qs.order_by('pk').last()
        if last_record:
            qs = qs.filter(pk__gt=last_record.pk - 50000)
        return qs.only(
            'contest__name', 'contest__format_name', 'contest__format_config',
            'user__user__username', 'real_start', 'score', 'cumtime', 'tiebreaker', 'virtual',
        )

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if form.changed_data and 'is_disqualified' in form.changed_data:
            obj.set_disqualified(obj.is_disqualified)

    def recalculate_results(self, request, queryset):
        count = 0
        for participation in queryset:
            participation.recompute_results()
            count += 1
        self.message_user(request, ngettext('%d participation recalculated.',
                                            '%d participations recalculated.',
                                            count) % count)
    recalculate_results.short_description = _('Recalculate results')

    def username(self, obj):
        return obj.user.username
    username.short_description = _('username')
    username.admin_order_field = 'user__user__username'

    def show_virtual(self, obj):
        return obj.virtual or '-'
    show_virtual.short_description = _('virtual')
    show_virtual.admin_order_field = 'virtual'


class ContestSubmissionAdmin(admin.ModelAdmin):
    fields = ('problem', 'submission', 'participation', 'is_pretest', 'points')
    readonly_fields = ('problem', 'submission', 'participation')
