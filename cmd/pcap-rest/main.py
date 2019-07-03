from gevent import monkey
monkey.patch_all()
from bottle import run

from app import app, read_config
from logger import init_logger

LISTEN_PORT = 20205


if __name__ == '__main__':
    init_logger()
    read_config()
    run(app, host='0.0.0.0', port=LISTEN_PORT, debug=False, server='gevent')
