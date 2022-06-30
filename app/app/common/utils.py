import json
import aiohttp

from sanic.response import json as sanic_json
from functools import wraps
from schematics.exceptions import ModelConversionError, ModelValidationError

from log import logger
from common import const
from common import exceptions

log = logger.getLogger(__name__)

async def curl_perform(func, url=None, data=None, headers=None, timeout=10):
    data = json.dumps(data)
    if headers == None:
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/plain',
            'X-User-Id': '1',
            'X-User-Type': '1'
        }
    async with aiohttp.ClientSession() as session:
        async with getattr(session, func)(
            url, data=data, headers=headers, timeout=timeout
        ) as r:
            response = await r.read()
            response = json.loads(response)
            status_code = r.status
    return response, status_code


def format_response(
    type_name, status, response, debug=False, fail_regions=None, total=None
):
    result_dict = {"type": type_name}
    status_code = status.get_status()
    result_dict["description"] = ''
    result_dict["status"] = const.SUCCESS
    if status_code != 200:
        result_dict[
            "description"
        ] = status.description if status.description else f"查询数据区域失败：{'，'.join(fail_regions)}"
        result_dict["status"] = const.PARTIAL_RESULT
    result_dict["data"] = response
    if total:
        result_dict["count"] = total
    if debug:
        debug_info = status.to_querier_debug()
        result_dict["tsdb_info"] = debug_info.get("_TSDB_INFO", {})
        result_dict["query_ids"] = debug_info.get("_QUERY_IDS", [])
    return result_dict, status_code


def dict_response(
    status=const.SUCCESS, description=None, data=None, page=None, db_type=None,
    db_table=None, db_query=None, db_name=None, query_ids=None, count=None,
    tsdb_info=None, type=None, **garbage_collector
):
    if description is None:
        description = ''
    info = {'OPT_STATUS': status, 'DESCRIPTION': description}
    if data is not None:
        info['DATA'] = data
    if page is not None:
        info['PAGE'] = page
    if db_type is not None:
        info['DB_TYPE'] = db_type
    if db_table is not None:
        info['DB_TABLE'] = db_table
    if db_query is not None:
        info['DB_QUERY'] = db_query
    if db_name is not None:
        info['DB_NAME'] = db_name
    if query_ids is not None:
        info['_QUERY_IDS'] = query_ids
    if tsdb_info is not None:
        info['_TSDB_INFO'] = tsdb_info
    if count is not None:
        info['COUNT'] = count
    if type is not None:
        info['TYPE'] = type
    return info


def json_response(
    status=const.SUCCESS, description=None, data=None, dict_data=None, page=None,
    db_type=None, db_table=None, db_query=None, db_name=None, query_ids=None,
    count=None, tsdb_info=None, type=None, **garbage_collector
):
    if dict_data is not None:
        return dict_data
    else:
        return dict_response(
            status, description, data, page, db_type, db_table, db_query,
            db_name, query_ids, count, tsdb_info, type
        )

def app_exception(function):
    
    @wraps(function)
    async def wrapper(*args, **kwargs):
        try:
            response = await function(*args, **kwargs)
            return response
        except (ModelConversionError, ModelValidationError) as error:
            response = json_response(
                status=const.INVALID_POST_DATA, description=str(error)
            )
            code = const.HTTP_BAD_REQUEST

        except exceptions.BadRequestException as error:
            response = json_response(
                status=error.status, description=str(error)
            )
            code = const.HTTP_BAD_REQUEST
        except exceptions.NotAllowMethodException as error:
            response = json_response(
                status='NOT_ALLOW_METHOD', description=str(error)
            )
            code = const.HTTP_NOT_ALLOWED
        except exceptions.TrafficPropertyException as error:
            response = json_response(
                status=error.status, description=str(error)
            )
            code = const.HTTP_BAD_REQUEST

        except Exception as error:
            log.exception(error)
            response = json_response(
                status='INTERNAL_SERVER_ERROR', description=str(error)
            )
            code = const.HTTP_INTERNAL_SERVER_ERROR
        return sanic_json(response, content_type=const.JSON_TYPE, status=code)

    return wrapper