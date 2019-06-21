# -*- coding: utf-8 -*-
import os
import sys
import logging
from logging.handlers import SysLogHandler
from logging.handlers import TimedRotatingFileHandler


class LcTimedRotatingFileHandler(TimedRotatingFileHandler):

    def __init__(self, *args, **kwargs):
        TimedRotatingFileHandler.__init__(self, *args, **kwargs)
        # redirect stderr to log file
        os.dup2(self.stream.fileno(), sys.stderr.fileno())

    def doRollover(self):
        TimedRotatingFileHandler.doRollover(self)
        # redirect stderr to log file
        os.dup2(self.stream.fileno(), sys.stderr.fileno())


def init(
    daemon=False, logger_file='', name_dict={}, module_dict={}, module_name='',
    handler_class=LcTimedRotatingFileHandler
):
    if daemon:
        log_handler = handler_class(logger_file, when='midnight')
    else:
        log_handler = logging.StreamHandler()

    log_formatter = logging.Formatter(
        '%(asctime)s T%(thread)d-%(threadName)s '
        '%(levelname)s %(module)s.'
        '%(funcName)s.%(lineno)s: %(message)s'
    )
    log_handler.setFormatter(log_formatter)

    if module_name:
        syslog_handler = SysLogHandler(
            address='/dev/log', facility=SysLogHandler.LOG_LOCAL2
        )
        syslog_formatter = \
            logging.Formatter(module_name + '/%(module)s: %(message)s')
        syslog_handler.setFormatter(syslog_formatter)
        syslog_filter = logging.Filter()
        syslog_filter.filter = lambda record: \
            record.levelno == logging.WARNING or \
            record.levelno == logging.ERROR
        syslog_handler.addFilter(syslog_filter)

    _default_name_level = {
        __name__: logging.DEBUG,
        "__main__": logging.DEBUG,
    }
    _name_dict = dict()
    _name_dict.update(_default_name_level)
    _name_dict.update(name_dict)

    for name, level in _name_dict.items():
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.addHandler(log_handler)
        if module_name:
            logger.addHandler(syslog_handler)
    for module_logger, level in module_dict.items():
        module_logger.setLevel(level)
        module_logger.addHandler(log_handler)
        if module_name:
            logger.addHandler(syslog_handler)


def init_logger():
    name_dict = {
        'pcap': logging.DEBUG,
        '__main__': logging.DEBUG,
    }
    init(
        daemon=os.getppid() == 1, logger_file="/var/log/pcap-rest.log", name_dict=name_dict,
        module_name='pcap-rest'
    )
