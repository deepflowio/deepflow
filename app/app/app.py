#!/usr/bin/env python3

import signal
import socket
import sys

import server
from config import config
from log import logger, sanic_logger
from common.const import WORKER_NUMBER

log = logger.getLogger(__name__)


def signal_handler(sig, frame):
    if sig == signal.SIGTERM:
        log.info('Terminating Cleaner ...')
        sys.exit(0)
    elif sig == signal.SIGHUP:
        log.info('Reloading statistics.yaml ...')
        config.is_valid()
        log.info('statistics.yaml reloaded.')


async def notify_server_started(app, loop):
    pass


async def before_server_stop(app, loop):
    pass


def main():
    logger_manager = logger.LoggerManager(
        'metaflow-app', config.log_level, config.log_file
    )
    logger_manager.init_logger()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    log.info('Launching Metaflow-app ...')
    server.server.register_listener(notify_server_started, 'before_server_start')
    server.server.register_listener(before_server_stop, 'before_server_stop')

    server.init(config.http_request_timeout, config.http_response_timeout)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.bind(('', config.listen_port))
    server.server.run(
        workers=WORKER_NUMBER, sock=sock, protocol=sanic_logger.DFHttpProtocol
    )


if __name__ == '__main__':
    main()
