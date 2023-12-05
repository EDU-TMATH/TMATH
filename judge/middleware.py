import base64
import hmac
import logging
import re
import struct
from urllib.parse import quote as urlquote

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import Resolver404, resolve, reverse
from django.utils.encoding import force_bytes
from requests.exceptions import HTTPError

logger = logging.getLogger('judge.request')


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class LogRequestsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = "AnonymousUser" if request.user.is_anonymous else request.user.username
        ip = get_client_ip(request)
        # Log the user access URL
        info = f"User {user} in IP:{ip} accessed {request.path} - {request.method}"
        logger.info(info)

        response = self.get_response(request)
        return response


# One session_key to one Person anytime
class OneSessionPerUser(object):
    def __init__(self, get_response) -> None:
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            current_session_key = request.user.logged_in_user.session_key

            if current_session_key and current_session_key != request.session.session_key:
                Session.objects.filter(session_key=current_session_key).delete()

            request.user.logged_in_user.session_key = request.session.session_key
            request.user.logged_in_user.save()

        return self.get_response(request)


class ShortCircuitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            callback, args, kwargs = resolve(request.path_info, getattr(request, 'urlconf', None))
        except Resolver404:
            callback, args, kwargs = None, None, None

        if getattr(callback, 'short_circuit_middleware', False):
            return callback(request, *args, **kwargs)
        return self.get_response(request)


class DMOJLoginMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            request.profile = request.user.profile
            logout_path = reverse('auth_logout')
            # webauthn_path = reverse('webauthn_assert')
            change_password_path = reverse('password_change')
            change_password_done_path = reverse('password_change_done')
            # has_2fa = profile.is_totp_enabled or profile.is_webauthn_enabled
            # if (has_2fa and not request.session.get('2fa_passed', False) and
            #         request.path not in (login_2fa_path, logout_path, webauthn_path) and
            #         not request.path.startswith(settings.STATIC_URL)):
            #     return HttpResponseRedirect(login_2fa_path + '?next=' + urlquote(request.get_full_path()))
            if (request.session.get('password_pwned', False) and
                    request.path not in (change_password_path, change_password_done_path,
                                         logout_path) and
                    not request.path.startswith(settings.STATIC_URL)):
                return HttpResponseRedirect(change_password_path + '?next=' + urlquote(request.get_full_path()))
        else:
            request.profile = None
        return self.get_response(request)


class DMOJImpersonationMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_impersonate:
            request.no_profile_update = True
            request.profile = request.user.profile
        return self.get_response(request)


class ContestMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        profile = request.profile
        if profile:
            profile.update_contest()
            request.participation = profile.current_contest
            request.in_contest = request.participation is not None
        else:
            request.in_contest = False
            request.participation = None
        return self.get_response(request)


# class TypoMiddleware(object):
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         with transaction.atomic():
#             for room in TypoRoom.objects.all().exclude(contest=None):
#                 if room.contest.ended and room.is_random:
#                     room.contest = None
#                     room.save()
#         if request.user.is_authenticated:
#             profile = request.user.profile
#         else:
#             profile = None
#         if profile:
#             profile.update_typo()
#         return self.get_response(request)


class APIMiddleware(object):
    header_pattern = re.compile('^Bearer ([a-zA-Z0-9_-]{48})$')

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        full_token = request.META.get('HTTP_AUTHORIZATION', '')
        if not full_token:
            return self.get_response(request)

        token = self.header_pattern.match(full_token)
        if not token:
            return HttpResponse('Invalid authorization header', status=400)
        if request.path.startswith(reverse('admin:index')):
            return HttpResponse('Admin inaccessible', status=403)

        try:
            id, secret = struct.unpack('>I32s', base64.urlsafe_b64decode(token.group(1)))
            request.user = User.objects.get(id=id)

            # User hasn't generated a token
            if not request.user.profile.api_token:
                raise HTTPError()

            # Token comparison
            digest = hmac.new(force_bytes(settings.SECRET_KEY), msg=secret, digestmod='sha256').hexdigest()
            if not hmac.compare_digest(digest, request.user.profile.api_token):
                raise HTTPError()

            request._cached_user = request.user
            request.csrf_processing_done = True
            request.session['2fa_passed'] = True
        except (User.DoesNotExist, HTTPError):
            response = HttpResponse('Invalid token')
            response['WWW-Authenticate'] = 'Bearer realm="API"'
            response.status_code = 401
            return response
        return self.get_response(request)
