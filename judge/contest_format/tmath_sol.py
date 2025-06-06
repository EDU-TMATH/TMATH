from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import connection
from django.template.defaultfilters import floatformat
from django.utils.translation import gettext_lazy

from judge.contest_format.default import DefaultContestFormat
from judge.contest_format.registry import register_contest_format
from judge.timezone import from_database_time
from judge.utils.timedelta import nice_repr


@register_contest_format('tmath_sol')
class TmathContestFormat(DefaultContestFormat):
    name = gettext_lazy('Tmath Solution')
    config_defaults = {'penalty': 20, 'weight': 0.98}
    config_validators = {'penalty': lambda x: x >= 0, 'weight': lambda x: x > 0 and x <= 1}
    '''
        penalty: Number of penalty minutes each incorrect submission adds. Defaults to 20.
        weight: Points decrease after each failed submission.
    '''

    @classmethod
    def validate(cls, config):
        if config is None:
            return

        if not isinstance(config, dict):
            raise ValidationError('Tmath-styled contest expects no config or dict as config')

        for key, value in config.items():
            if key not in cls.config_defaults:
                raise ValidationError('unknown config key "%s"' % key)
            if not isinstance(value, type(cls.config_defaults[key])):
                raise ValidationError('invalid type for config key "%s"' % key)
            if not cls.config_validators[key](value):
                raise ValidationError('invalid value "%s" for config key "%s"' % (value, key))

    def __init__(self, contest, config):
        self.config = self.config_defaults.copy()
        self.config.update(config or {})
        self.contest = contest

    def update_participation(self, participation):
        cumtime = 0
        last = 0
        penalty = 0
        score = 0
        format_data = {}

        with connection.cursor() as cursor:
            cursor.execute('''
                SELECT MAX(cs.points) as `points`, (
                    SELECT MIN(csub.date)
                        FROM judge_contestsubmission ccs LEFT OUTER JOIN
                             judge_submission csub ON (csub.id = ccs.submission_id)
                        WHERE ccs.problem_id = cp.id AND ccs.participation_id = %s AND ccs.points = MAX(cs.points)
                ) AS `time`, cp.id AS `prob`
                FROM judge_contestproblem cp INNER JOIN
                     judge_contestsubmission cs ON (cs.problem_id = cp.id AND cs.participation_id = %s) LEFT OUTER JOIN
                     judge_submission sub ON (sub.id = cs.submission_id)
                GROUP BY cp.id
            ''', (participation.id, participation.id))

            for points, time, prob in cursor.fetchall():
                time = from_database_time(time)
                dt = (time - participation.start).total_seconds()

                # Compute penalty
                if self.config['penalty']:
                    # An IE can have a submission result of `None`
                    subs = participation.submissions.exclude(submission__result__isnull=True) \
                                                    .exclude(submission__result__in=['IE', 'CE']) \
                                                    .filter(problem_id=prob)
                    if points:
                        prev = subs.filter(submission__date__lte=time).count() - 1
                        penalty += prev * self.config['penalty'] * 60
                        points *= self.config['weight'] ** prev
                    else:
                        # We should always display the penalty, even if the user has a score of 0
                        prev = subs.count()
                else:
                    prev = 0

                if points:
                    cumtime += dt
                    last = max(last, dt)

                format_data[str(prob)] = {'time': dt, 'points': points, 'penalty': prev}
                score += points
        # print(format_data)
        participation.cumtime = max(cumtime, 0) + penalty
        participation.score = round(score, self.contest.points_precision)
        participation.tiebreaker = last  # field is sorted from least to greatest
        participation.format_data = format_data
        participation.save()

    def display_user_problem(self, participation, contest_problem):
        format_data = (participation.format_data or {}).get(str(contest_problem.id))
        if format_data:
            point = contest_problem.points * (self.config['weight'] ** format_data['penalty'])
            return {
                'has_data': True,
                'problem': contest_problem.order,
                'username': participation.user.user.username,
                'penalty': floatformat(format_data['penalty']) if format_data['penalty'] else -1,
                'points': floatformat(format_data['points']),
                'time': nice_repr(timedelta(seconds=format_data['time']), 'noday'),
                'state': (('pretest-' if self.contest.run_pretests_only and contest_problem.is_pretested else '') +
                          self.best_solution_state(format_data['points'], point)),
            }
        else:
            return {
                'has_data': False,
                'state': 'unsubmitted',
            }

    def get_label_for_problem(self, index):
        index += 1
        ret = ''
        while index > 0:
            ret += chr((index - 1) % 26 + 65)
            index = (index - 1) // 26
        return ret[::-1]
