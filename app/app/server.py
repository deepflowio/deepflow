from sanic import Sanic

from application.application import application_app

server = Sanic(__name__)
server.blueprint(application_app)


@server.middleware('request')
async def request_started(request):
    pass


@server.middleware('response')
async def request_finished(request, response):
    pass


def init(request_timeout, response_timeout):
    server.config.REQUEST_TIMEOUT = request_timeout
    server.config.RESPONSE_TIMEOUT = response_timeout
