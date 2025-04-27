from django.apps import AppConfig
from django.utils.translation import gettext_lazy


class JudgeAppConfig(AppConfig):
    name = "judge"
    verbose_name = gettext_lazy("Online Judge")

    def ready(self):
        # WARNING: AS THIS IS NOT A FUNCTIONAL PROGRAMMING LANGUAGE,
        #          OPERATIONS MAY HAVE SIDE EFFECTS.
        #          DO NOT REMOVE THINKING THE import IS UNUSED.
        # noinspection PyUnresolvedReferences
        # from datetime import datetime

        # import pytz

        # from chat.models import ChatParticipation, ChatRoom
        # from judge.models import Organization

        from . import jinja2, signals  # noqa: F401, imported for side effects

        # Change timezone from Asia/SaiGon to Asia/Ho_Chi_Minh
        # from judge.models import Profile
        # Profile.objects.filter(timezone='Asia/SaiGon').update(timezone='Asia/Ho_Chi_Minh')
        # from judge.models import ProblemData
        # from pathlib import Path
        # Remove all zip file that not exist
        # for data in ProblemData.objects.filter(zipfile__isnull=False):
        #     filename = data.zipfile.name
        #     # Check url is exist zip file
        #     if Path('/mnt/problems/' + filename).exists():
        #         continue
        #     else:
        #         data.zipfile = None
        #         data.save()
