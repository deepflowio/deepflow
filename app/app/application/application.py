from sanic import Blueprint
from sanic.response import json as Response

from log import logger

from common.utils import json_response, format_response, app_exception
from common.const import API_PREFIX

from .l7_flow_tracing import L7FlowTracing
from models.models import FlowLogL7Tracing

log = logger.getLogger(__name__)

application_app = Blueprint(__name__, url_prefix=API_PREFIX + '/querier')
@application_app.route('/L7FlowTracing', methods=['POST'])
@app_exception
async def application_log_l7_tracing(request):
    args = FlowLogL7Tracing(request.json)
    args.validate()
    status, response, failed_regions = await L7FlowTracing(
        args, request.headers
    ).query()
    response_dict, code = format_response(
        "Flow_Log_L7_Tracing", status, response, args.debug, failed_regions
    )
    return Response(
        json_response(**response_dict),
        content_type='application/json; charset=utf-8', status=code
    )
