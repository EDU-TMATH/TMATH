import base64
import datetime
import hmac
import json
import secrets
import struct
from operator import mul

import pyotp
import webauthn
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import F, Max
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.functional import cached_property
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
# from fernet_fields import EncryptedCharField
from pyotp.utils import strings_equal

from judge.models.choices import (ACE_THEMES, MATH_ENGINES_CHOICES, NEWBIE,
                                  RATE, TIMEZONE)
from judge.models.runtime import Language
# from judge.models.contest import RATE, NEWBIE
from judge.ratings import rating_class
from judge.utils.two_factor import webauthn_decode

# from sortedm2m.fields import SortedManyToManyField


__all__ = ['Organization', 'Profile', 'OrganizationRequest', 'WebAuthnCredential', 'LoggedInUser']


class LoggedInUser(models.Model):

    user = models.OneToOneField(User, related_name='logged_in_user', on_delete=models.CASCADE)
    session_key = models.CharField(max_length=32, blank=True, null=True)

    class Meta:
        verbose_name = _("loggedinuser")
        verbose_name_plural = _("loggedinusers")

    def __str__(self):
        return self.user.username


class SchoolYear(models.Model):
    start = models.DateField(_("year start"))
    finish = models.DateField(_("year finish"))

    def __str__(self):
        return "%s - %s" % (self.start.year, self.finish.year)

    def clean(self) -> None:
        if self.start and self.finish and self.start >= self.finish:
            raise ValidationError('What is this? A school year that ended before it starts?')


class Organization(models.Model):
    name = models.CharField(max_length=128, verbose_name=_('organization title'))
    slug = models.SlugField(max_length=128, verbose_name=_('organization slug'),
                            help_text=_('Organization name shown in URL'))
    short_name = models.CharField(max_length=20, verbose_name=_('short name'),
                                  help_text=_('Displayed beside user name during contests'))
    about = models.TextField(verbose_name=_('organization description'), db_collation='utf8mb4_unicode_ci')
    admins = models.ManyToManyField('Profile', verbose_name=_('administrators'), related_name='admin_of',
                                    help_text=_('Those who can edit this organization'))
    creation_date = models.DateTimeField(verbose_name=_('creation date'), auto_now_add=True)
    is_open = models.BooleanField(verbose_name=_('is open organization?'),
                                  help_text=_('Allow joining organization'), default=True)
    slots = models.IntegerField(verbose_name=_('maximum size'), null=True, blank=True,
                                help_text=_('Maximum amount of users in this organization, '
                                            'only applicable to private organizations'))
    access_code = models.CharField(max_length=7, help_text=_('Student access code'),
                                   verbose_name=_('access code'), null=True, blank=True)
    logo_override_image = models.CharField(verbose_name=_('Logo override image'), default='', max_length=150,
                                           blank=True,
                                           help_text=_('This image will replace the default site logo for users '
                                                       'viewing the organization.'))
    rate = models.IntegerField(_("Rate of Organization"), default=NEWBIE, choices=RATE)
    year = models.ForeignKey(SchoolYear, verbose_name=_("school year"), on_delete=models.SET_NULL, null=True)

    def __contains__(self, item):
        if isinstance(item, int):
            return self.members.filter(id=item).exists()
        elif isinstance(item, Profile):
            return self.members.filter(id=item.id).exists()
        else:
            raise TypeError('Organization membership test must be Profile or primany key')

    def __str__(self):
        return self.name

    @property
    def room(self):
        room = self.chat_room.all().first()
        return room

    @cached_property
    def in_organization(self, user):
        return self.members.filter(id=user.id).exists()

    def get_absolute_url(self):
        return reverse('organization_home', args=(self.id, self.slug))

    def get_users_url(self):
        return reverse('organization_users', args=(self.id, self.slug))

    class Meta:
        ordering = ['name']
        permissions = (
            ('organization_admin', _('Administer organizations')),
            ('edit_all_organization', _('Edit all organizations')),
        )
        verbose_name = _('organization')
        verbose_name_plural = _('organizations')


def get_default_time():
    return now() - datetime.timedelta(days=30)


class Profile(models.Model):
    user = models.OneToOneField(User, verbose_name=_('user associated'), on_delete=models.CASCADE)
    name = models.CharField(max_length=255, null=True)
    about = models.TextField(verbose_name=_('self-description'), null=True, blank=True,
                             db_collation='utf8mb4_unicode_ci')
    timezone = models.CharField(max_length=50, verbose_name=_('location'), choices=TIMEZONE,
                                default=settings.DEFAULT_USER_TIME_ZONE)
    language = models.ForeignKey('Language', verbose_name=_('preferred language'), on_delete=models.SET_DEFAULT,
                                 default=Language.get_default_language_pk)
    points = models.FloatField(default=0, db_index=True)
    performance_points = models.FloatField(default=0, db_index=True)
    problem_count = models.IntegerField(default=0, db_index=True)
    ace_theme = models.CharField(max_length=30, choices=ACE_THEMES, default='github')
    last_access = models.DateTimeField(verbose_name=_('last access time'), default=now)
    ip = models.GenericIPAddressField(verbose_name=_('last IP'), blank=True, null=True)
    organizations = models.ManyToManyField(Organization, verbose_name=_('organization'), blank=True,
                                           related_name='members', related_query_name='member')
    display_rank = models.CharField(max_length=10, default='user', verbose_name=_('display rank'),
                                    choices=(
                                        ('user', _('Normal User')),
                                        ('setter', _('Problem Setter')),
                                        ('admin', _('Admin'))))
    mute = models.BooleanField(verbose_name=_('comment mute'), help_text=_('Some users are at their best when silent.'),
                               default=False)
    is_unlisted = models.BooleanField(verbose_name=_('unlisted user'), help_text=_('User will not be ranked.'),
                                      default=False)
    rating = models.IntegerField(null=True, default=None)
    user_script = models.TextField(verbose_name=_('user script'), default='', blank=True, max_length=65536,
                                   help_text=_('User-defined JavaScript for site customization.'))
    current_contest = models.OneToOneField('ContestParticipation', verbose_name=_('current contest'),
                                           null=True, blank=True, related_name='+', on_delete=models.SET_NULL)
    math_engine = models.CharField(verbose_name=_('math engine'), choices=MATH_ENGINES_CHOICES, max_length=4,
                                   default=settings.MATHOID_DEFAULT_TYPE,
                                   help_text=_('the rendering engine used to render math'))
    # is_totp_enabled = models.BooleanField(verbose_name=_('TOTP 2FA enabled'), default=False,
    #                                       help_text=_('check to enable TOTP-based two-factor authentication'))
    is_webauthn_enabled = models.BooleanField(verbose_name=_('WebAuthn 2FA enabled'), default=False,
                                              help_text=_('check to enable WebAuthn-based two-factor authentication'))
    # totp_key = EncryptedNullCharField(max_length=32, null=True, blank=True, verbose_name=_('TOTP key'),
    #                                   help_text=_('32 character base32-encoded key for TOTP'),
    #                                   validators=[RegexValidator('^$|^[A-Z2-7]{32}$',
    #                                                              _('TOTP key must be empty or base32'))])
    # scratch_codes = EncryptedNullCharField(max_length=255, null=True, blank=True, verbose_name=_('scratch codes'),
    #                                        help_text=_('JSON array of 16 character base32-encoded codes \
    #                                                     for scratch codes'),
    #                                        validators=[
    #                                            RegexValidator(r'^(\[\])?$|^\[("[A-Z0-9]{16}", *)*"[A-Z0-9]{16}"\]$',
    #                                                           _('Scratch codes must be empty or a JSON array of \
    #                                                              16-character base32 codes'))])
    # last_totp_timecode = models.IntegerField(verbose_name=_('last TOTP timecode'), default=0)
    api_token = models.CharField(max_length=64, null=True, verbose_name=_('API token'),
                                 help_text=_('64 character hex-encoded API access token'),
                                 validators=[RegexValidator('^[a-f0-9]{64}$',
                                                            _('API token must be None or hexadecimal'))])
    notes = models.TextField(verbose_name=_('internal notes'), null=True, blank=True,
                             help_text=_('Notes for administrators regarding this user.'))
    data_last_downloaded = models.DateTimeField(verbose_name=_('last data download time'), null=True, blank=True)
    last_change_name = models.DateTimeField(_("last change fullname"), default=get_default_time)
    last_name = models.CharField(_("prev name"), max_length=255, null=True, default=None)
    verified = models.BooleanField(_("verified"), default=False)
    expiration_date = models.DateTimeField(null=True, blank=True)
    super_admin = models.BooleanField(_("super admin"), default=False)
    can_download_all_testcases = models.BooleanField(_("can download all testcases"), default=False)

    @cached_property
    def organization(self):
        # We do this to take advantage of prefetch_related
        orgs = self.organizations.all()
        return orgs[0] if orgs else None

    @cached_property
    def username(self):
        return self.user.username

    @cached_property
    def has_any_solves(self):
        return self.submission_set.filter(points=F('problem__points')).exists()

    _pp_table = [pow(settings.DMOJ_PP_STEP, i) for i in range(settings.DMOJ_PP_ENTRIES)]

    def calculate_points(self, table=_pp_table):
        from judge.models import Problem
        public_problems = Problem.get_public_problems()
        data = (
            public_problems.filter(submission__user=self, submission__points__isnull=False)
                           .annotate(max_points=Max('submission__points')).order_by('-max_points')
                           .values_list('max_points', flat=True).filter(max_points__gt=0)
        )
        extradata = (
            public_problems.filter(submission__user=self, submission__result='AC').values('id').distinct().count()
        )
        bonus_function = settings.DMOJ_PP_BONUS_FUNCTION
        points = sum(data)
        problems = len(data)
        entries = min(len(data), len(table))
        pp = sum(map(mul, table[:entries], data[:entries])) + bonus_function(extradata)
        if self.points != points or problems != self.problem_count or self.performance_points != pp:
            self.points = points
            self.problem_count = problems
            self.performance_points = pp
            self.save(update_fields=['points', 'problem_count', 'performance_points'])
        return points

    calculate_points.alters_data = True

    def generate_api_token(self):
        secret = secrets.token_bytes(32)
        self.api_token = hmac.new(force_bytes(settings.SECRET_KEY), msg=secret, digestmod='sha256').hexdigest()
        self.save(update_fields=['api_token'])
        token = base64.urlsafe_b64encode(struct.pack('>I32s', self.user.id, secret))
        return token.decode('utf-8')

    generate_api_token.alters_data = True

    def generate_scratch_codes(self):
        def generate_scratch_code():
            return "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
        codes = [generate_scratch_code() for _ in range(settings.DMOJ_SCRATCH_CODES_COUNT)]
        self.scratch_codes = json.dumps(codes)
        self.save(update_fields=['scratch_codes'])
        return codes

    generate_scratch_codes.alters_data = True

    def remove_contest(self):
        self.current_contest = None
        self.save()

    remove_contest.alters_data = True

    def update_contest(self):
        contest = self.current_contest
        if contest is not None and (contest.ended or not contest.contest.is_joinable_by(self.user)):
            self.remove_contest()

    update_contest.alters_data = True

    def check_totp_code(self, code):
        totp = pyotp.TOTP(self.totp_key)
        now_timecode = totp.timecode(timezone.now())
        min_timecode = max(self.last_totp_timecode + 1, now_timecode - settings.DMOJ_TOTP_TOLERANCE_HALF_MINUTES)
        for timecode in range(min_timecode, now_timecode + settings.DMOJ_TOTP_TOLERANCE_HALF_MINUTES + 1):
            if strings_equal(code, totp.generate_otp(timecode)):
                self.last_totp_timecode = timecode
                self.save(update_fields=['last_totp_timecode'])
                return True
        return False

    check_totp_code.alters_data = True

    def get_absolute_url(self):
        return reverse('user_page', args=(self.user.username,))

    def __str__(self):
        return self.user.username

    @classmethod
    def get_user_css_class(cls, display_rank, rating, rating_colors=settings.DMOJ_RATING_COLORS):
        if rating_colors:
            return 'rating %s %s' % (rating_class(rating) if rating is not None else 'rate-none', display_rank)
        return display_rank

    @cached_property
    def css_class(self):
        return self.get_user_css_class(self.display_rank, self.rating)

    @cached_property
    def webauthn_id(self):
        return hmac.new(force_bytes(settings.SECRET_KEY), msg=b'webauthn:%d' % (self.id,), digestmod='sha256').digest()

    def pre_save(self):
        pass

    def save(self, force_insert=False, force_update=False, *args, **kwargs):
        if not self.verified and self.name != self.last_name:
            self.last_change_name = timezone.now() - datetime.timedelta(days=30) * (self.last_name is None)
            self.last_name = self.name
        return super().save(force_insert, force_update, *args, **kwargs)

    class Meta:
        ordering = ['id']
        permissions = (
            ('test_site', _('Shows in-progress development stuff')),
            ('totp', _('Edit TOTP settings')),
        )
        verbose_name = _('user profile')
        verbose_name_plural = _('user profiles')


class WebAuthnCredential(models.Model):
    user = models.ForeignKey(Profile, verbose_name=_('user'), related_name='webauthn_credentials',
                             on_delete=models.CASCADE)
    name = models.CharField(verbose_name=_('device name'), max_length=100)
    cred_id = models.CharField(verbose_name=_('credential ID'), max_length=255, unique=True)
    public_key = models.TextField(verbose_name=_('public key'))
    counter = models.BigIntegerField(verbose_name=_('sign counter'))

    @cached_property
    def webauthn_user(self):
        from judge.jinja2.gravatar import gravatar

        return webauthn.WebAuthnUser(
            user_id=self.user.webauthn_id,
            username=self.user.username,
            display_name=self.user.username,
            icon_url=gravatar(self.user.user.email),
            credential_id=webauthn_decode(self.cred_id),
            public_key=self.public_key,
            sign_count=self.counter,
            rp_id=settings.WEBAUTHN_RP_ID,
        )

    def __str__(self):
        return f'WebAuthn credential: {self.name}'

    class Meta:
        verbose_name = _('WebAuthn credential')
        verbose_name_plural = _('WebAuthn credentials')


class OrganizationRequest(models.Model):
    user = models.ForeignKey(Profile, verbose_name=_('user'), related_name='requests', on_delete=models.CASCADE)
    admin = models.ForeignKey(Profile, verbose_name=_('admin'), null=True, blank=True,
                              related_name='actions', on_delete=models.SET_NULL)
    organization = models.ForeignKey(Organization, verbose_name=_('organization'), related_name='requests',
                                     on_delete=models.CASCADE)
    time = models.DateTimeField(verbose_name=_('request time'), auto_now_add=True)
    state = models.CharField(max_length=1, verbose_name=_('state'), choices=(
        ('P', 'Pending'),
        ('A', 'Approved'),
        ('R', 'Rejected'),
        ('L', 'Leaved'),
        ('K', 'Kicked'),
    ))
    reason = models.TextField(verbose_name=_('reason'))

    class Meta:
        verbose_name = _('organization join request')
        verbose_name_plural = _('organization join requests')
