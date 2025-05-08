import random

from django.conf import settings
from django.contrib.auth.context_processors import PermWrapper
from django.contrib.auth.models import AnonymousUser
from django.contrib.sites.shortcuts import get_current_site
from django.core.cache import cache
from django.urls import reverse
from django.utils.functional import SimpleLazyObject, new_method_proxy
from django.utils.translation import gettext_lazy as _

from judge.models import MiscConfig, NavigationBar, Profile
from judge.utils.caniuse import CanIUse


class FixedSimpleLazyObject(SimpleLazyObject):
    if not hasattr(SimpleLazyObject, "__iter__"):
        __iter__ = new_method_proxy(iter)


def get_resource(request):
    use_https = settings.DMOJ_SSL
    if use_https == 1:
        scheme = "https" if request.is_secure() else "http"
    elif use_https > 1:
        scheme = "https"
    else:
        scheme = "http"
    return {
        "PYGMENT_THEME": settings.PYGMENT_THEME,
        "INLINE_JQUERY": settings.INLINE_JQUERY,
        "INLINE_FONTAWESOME": settings.INLINE_FONTAWESOME,
        "JQUERY_JS": settings.JQUERY_JS,
        "FONTAWESOME_CSS": settings.FONTAWESOME_CSS,
        # 'MATERIAL_ICONS': settings.MATERIAL_ICONS,
        "DMOJ_SCHEME": scheme,
        # 'DMOJ_CANONICAL': settings.DMOJ_CANONICAL,
        # 'CDN_SERVER' : settings.CDN_SERVER,
        "DEBUG": settings.DEBUG,
    }


def get_profile(request):
    user = getattr(request, "user", None)
    if user and user.is_authenticated:
        return Profile.objects.get_or_create(user=user)[0]
    return None


def __nav_tab(request):
    problem_link = reverse("problem_list")
    user = getattr(request, "user", None)
    if user and user.is_authenticated and user.profile.current_contest:
        problem_link = reverse(
            "contest_problem_list",
            args=[user.profile.current_contest.contest.key],
        )
    return [
        ("problem", problem_link, _("Problems")),
        ("submission", reverse("all_submissions"), _("Submissions")),
        ("user", reverse("user_list"), _("Users")),
        ("organization", reverse("organization_list"), _("Organizations")),
        ("contest", reverse("contest_list"), _("Contests")),
        ("about", "/about", _("About")),
    ]
    # result = list(NavigationBar.objects.extra(where=['%s REGEXP BINARY regex'], params=[path])[:1])
    # return result[0].get_ancestors(include_self=True).values_list('key', flat=True) if result else []


def general_info(request):
    path = request.get_full_path()
    version = getattr(settings, "STATIC_VERSION", random.randint(1, 1000000000))
    return {
        "nav_tab": __nav_tab(request),
        "nav_bar": NavigationBar.objects.all(),
        "LOGIN_RETURN_PATH": "" if path.startswith("/accounts/") else path,
        "perms": PermWrapper(getattr(request, "user", AnonymousUser())),
        "HAS_WEBAUTHN": bool(settings.WEBAUTHN_RP_ID),
        "version": version,
    }


def site(request):
    return {"site": get_current_site(request)}


class MiscConfigDict(dict):
    __slots__ = ("language", "site")

    def __init__(self, language="", domain=None):
        self.language = language
        self.site = domain
        super(MiscConfigDict, self).__init__()

    def __missing__(self, key):
        cache_key = "misc_config:%s:%s:%s" % (self.site, self.language, key)
        value = cache.get(cache_key)
        if value is None:
            keys = ["%s.%s" % (key, self.language), key] if self.language else [key]
            if self.site is not None:
                keys = ["%s:%s" % (self.site, key) for key in keys] + keys
            map = dict(
                MiscConfig.objects.values_list("key", "value").filter(key__in=keys),
            )
            for item in keys:
                if item in map:
                    value = map[item]
                    break
            else:
                value = ""
            cache.set(cache_key, value, 86400)
        self[key] = value
        return value


def misc_config(request):
    domain = get_current_site(request).domain
    return {"misc_config": MiscConfigDict(domain=domain)}


def site_name(request):
    return {
        "SITE_NAME": settings.SITE_NAME,
        "SITE_LONG_NAME": settings.SITE_LONG_NAME,
        "SITE_ADMIN_EMAIL": settings.SITE_ADMIN_EMAIL,
    }


def math_setting(request):
    caniuse = CanIUse(request.META.get("HTTP_USER_AGENT", ""))
    return {"MATH_ENGINE": "jax", "REQUIRE_JAX": True, "caniuse": caniuse}
