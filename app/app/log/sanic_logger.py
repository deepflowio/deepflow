from time import time
from sanic.server import HttpProtocol
from sanic.response import HTTPResponse

from .logger import getLogger

log = getLogger('df.sanic.access')


class DFHttpProtocol(HttpProtocol):

    def log_response(self, response):
        host = "Unknown"
        request = "None"
        status = getattr(response, "status", 0)
        byte = len(response.body) if isinstance(response, HTTPResponse) else -1
        time_elapsed = time() - self._last_request_time
        if self.request is not None:
            if self.request.ip:
                host = "%s:%s" % (self.request.ip, self.request.port)
            request = "%s %s" % (self.request.method, self.request.url)
        log.info(
            "%s %s %s %s %s" % (host, request, status, byte, time_elapsed)
        )
