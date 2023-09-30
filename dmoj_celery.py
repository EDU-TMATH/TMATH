import os

try:
    import MySQLdb  # noqa: F401, imported for side effect
except ImportError:
    import dmoj_install_pymysql  # noqa: F401, imported for side effect

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tmath.settings')

# noinspection PyUnresolvedReferences
from tmath.celery import app  # noqa: E402, F401, imported for side effect
