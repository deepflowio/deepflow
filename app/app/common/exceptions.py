from common.const import INVALID_PARAMETERS

__all__ = [
    'ConfException', 'StatisticsException', 'BadRequestException',
    'TrafficPropertyException'
]


class ConfException(Exception):

    message = None

    def __init__(self, message):
        Exception.__init__(self)
        self.message = message

    def __str__(self):
        return 'Statistics config Error: %s' % self.message


class BadRequestException(Exception):

    message = None

    def __init__(self, message, status=INVALID_PARAMETERS):
        Exception.__init__(self)
        self.message = message
        self.status = status

    def __str__(self):
        return 'Error (%s): %s' % (self.status, self.message)


class NotAllowMethodException(Exception):

    message = None

    def __init__(self, message):
        Exception.__init__(self)
        self.message = message

    def __str__(self):
        return 'not allow method: %s' % self.message


class TrafficPropertyException(Exception):

    message = None

    def __init__(self, message, status):
        Exception.__init__(self)
        self.message = message
        self.status = status

    def __str__(self):
        return 'Traffic Property Metric Error: %s' % self.message
