import math
import pandas as pd

from ast import Tuple
from pandas import DataFrame
from collections import defaultdict
from data.querier_client import Querier
from config import config
from .base import Base
from common import const

NET_SPAN_TAP_SIDE_PRIORITY = {
    item: i for i, item in enumerate(['c', 'c-nd', 's-nd', 's'])
}
L7_FLOW_TYPE_REQUEST = 0
L7_FLOW_TYPE_RESPONSE = 1
L7_FLOW_TYPE_SESSION = 2
TAP_SIDE_CLIENT_PROCESS = 'c-p'
TAP_SIDE_SERVER_PROCESS = 's-p'
TAP_SIDE_CLIENT_APP = 'c-app'
TAP_SIDE_SERVER_APP = 's-app'
RELATED_TYPE_BASE = 'base'
RELATED_TYPE_NETWORK = 'network'
RELATED_TYPE_APP = 'app'
RELATED_TYPE_SYSCALL = 'syscall'
RELATED_TYPE_TRACE_ID = 'traceid'
RELATED_TYPE_X_REQUEST_ID = 'x-request-id'
RETURN_FIELDS = list(
    set([
        # 追踪Meta信息
        "l7_protocol",
        "type",
        "req_tcp_seq",
        "resp_tcp_seq",
        "start_time_us",
        "end_time_us",
        "vtap_id",
        "tap_port",
        "tap_port_name",
        "tap_port_type",
        "resource_from_vtap",
        "syscall_trace_id_request",
        "syscall_trace_id_response",
        "syscall_cap_seq_0",
        "syscall_cap_seq_1",
        "trace_id",
        "span_id",
        "parent_span_id",
        "x_request_id",
        "_id",
        "flow_id",
        "protocol",
        "version",
        # 资源信息
        "process_id_0",
        "process_id_1",
        "tap_side",
        "subnet_id_0",
        "subnet_0",
        "ip_0",
        "resource_gl0_type_0",
        "resource_gl0_id_0",
        "resource_gl0_0",
        "resource_gl0_0_node_type",
        "resource_gl0_0_icon_id",
        "process_kname_0",
        "subnet_id_1",
        "subnet_1",
        "ip_1",
        "'attribute.service_name'",
        "resource_gl0_type_1",
        "resource_gl0_id_1",
        "resource_gl0_1",
        "resource_gl0_1_node_type",
        "resource_gl0_1_icon_id",
        "process_kname_1",
        "resource_gl2_type_0",
        "resource_gl2_id_0",
        "resource_gl2_0",
        "resource_gl2_type_1",
        "resource_gl2_id_1",
        "resource_gl2_1",
        # 指标信息
        "response_status",
        "response_duration",
        "response_code",
        "response_exception",
        "response_result",
        "request_type",
        "request_domain",
        "request_resource",
        "request_id",
        "http_proxy_client",
    ])
)
FIELDS_MAP = {
    "start_time_us": "toUnixTimestamp64Micro(start_time) as start_time_us",
    "end_time_us": "toUnixTimestamp64Micro(end_time) as end_time_us",
    "resource_gl0_0_node_type": "node_type(resource_gl0_0) as resource_gl0_0_node_type",
    "resource_gl0_0_icon_id": "icon_id(resource_gl0_0) as resource_gl0_0_icon_id",
    "resource_gl0_1_node_type": "node_type(resource_gl0_1) as resource_gl0_1_node_type",
    "resource_gl0_1_icon_id": "icon_id(resource_gl0_1) as resource_gl0_1_icon_id"
}
MERGE_KEYS = [
    'l7_protocol', 'protocol', 'version', 'request_type', 'request_domain',
    'request_resource', 'request_id', 'response_status', 'response_code',
    'response_exception', 'response_result', 'http_proxy_client', 'trace_id',
    'span_id', 'x_request_id'
]
MERGE_KEY_REQUEST = [
    'l7_protocol', 'protocol', 'version', 'request_type', 'request_domain',
    'request_resource', 'request_id'
]
MERGE_KEY_RESPONSE = [
    'response_status', 'response_code', 'response_exception',
    'response_result', 'http_proxy_client'
]
DATABASE = "flow_log"


class L7FlowTracing(Base):

    async def query(self):
        max_iteration = self.args.get("max_iteration", 30)
        network_delay_us = self.args.get("network_delay_us", 3000000)
        ntp_delay_us = self.args.get("ntp_delay_us", 10000)
        self.failed_regions = set()
        time_filter = f"time>={self.start_time} AND time<={self.end_time}"
        _id = self.args.get("_id")
        base_filter = f"_id={_id}"
        rst = await self.trace_l7_flow(
            time_filter=time_filter, base_filter=base_filter,
            return_fields=["related_type"], max_iteration=max_iteration,
            network_delay_us=network_delay_us, ntp_delay_us=ntp_delay_us
        )
        return self.status, rst, self.failed_regions

    async def trace_l7_flow(
        self, time_filter: str, base_filter: str, return_fields: list,
        max_iteration: int = 30, network_delay_us: int = 3000000,
        ntp_delay_us: int = 10000
    ) -> list:
        """L7 FlowLog 追踪入口
    
        参数说明：
        time_filter: 查询的时间范围过滤条件，SQL表达式
            当使用四元组进行追踪时，time_filter置为希望搜索的一段时间范围，
            当使用五元组进行追踪时，time_filter置为五元组对应流日志的start_time前后一小段时间，以提升精度
        base_filter: 查询的基础过滤条件，用于限定一个四元组或五元组
        return_fields: 返回l7_flow_log的哪些字段
    
        dedicated_vtap_ids: 专属服务器采集器ID列表
    
        max_iteration: 使用Flowmeta信息搜索的次数，每次搜索可认为大约能够扩充一级调用关系
        network_delay_us: 使用Flowmeta进行流日志匹配的时间偏差容忍度，越大漏报率越低但误报率越高，一般设置为网络时延的最大可能值
        """
        network_metas = set()
        syscall_metas = set()
        trace_ids = set()
        app_metas = set()
        x_request_ids = set()
        l7_flow_ids = set()

        dataframe_flowmetas = await self.query_flowmetas(
            time_filter, base_filter
        )
        if type(dataframe_flowmetas) != DataFrame:
            return []
        dataframe_flowmetas["related_type"] = RELATED_TYPE_BASE
        for i in range(max_iteration):
            if type(dataframe_flowmetas) != DataFrame:
                break

            # 新的网络追踪信息
            new_network_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['req_tcp_seq'][index] == 0 \
                    and dataframe_flowmetas['resp_tcp_seq'][index] == 0:
                    continue
                if dataframe_flowmetas['tap_side'][index] not in [
                    TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS
                ]:
                    continue
                new_network_metas.add((
                    dataframe_flowmetas['type'][index],
                    dataframe_flowmetas['req_tcp_seq'][index],
                    dataframe_flowmetas['resp_tcp_seq'][index],
                    dataframe_flowmetas['start_time_us'][index],
                    dataframe_flowmetas['end_time_us'][index]
                ))
            new_network_metas -= network_metas
            network_metas |= new_network_metas

            # 新的系统调用追踪信息
            new_syscall_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['syscall_trace_id_request'][index] > 0 and \
                    dataframe_flowmetas['syscall_trace_id_response'][index] > 0:
                    new_syscall_metas.add((
                        dataframe_flowmetas['vtap_id'][index],
                        dataframe_flowmetas['syscall_trace_id_request'][index],
                        dataframe_flowmetas['syscall_trace_id_response']
                        [index], dataframe_flowmetas['span_id'][index],
                        dataframe_flowmetas['x_request_id'][index]
                    ))
            new_syscall_metas -= syscall_metas
            syscall_metas |= new_syscall_metas

            # 新的应用span追踪信息
            new_app_metas = set()
            for index in range(len(dataframe_flowmetas.index)):
                if dataframe_flowmetas['tap_side'][index] not in [
                    TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS,
                    TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP
                ] or not dataframe_flowmetas['span_id'][index]:
                    continue
                if type(dataframe_flowmetas['span_id'][index]) == str and \
                    dataframe_flowmetas['span_id'][index] and \
                        type(dataframe_flowmetas['parent_span_id'][index]) == str and \
                            dataframe_flowmetas['parent_span_id'][index]:
                    new_app_metas.add((
                        dataframe_flowmetas['tap_side'][index],
                        dataframe_flowmetas['span_id'][index],
                        dataframe_flowmetas['parent_span_id'][index]
                    ))
            new_app_metas -= app_metas
            app_metas |= new_app_metas

            # 主动注入的追踪信息
            new_trace_ids = set([dataframe_flowmetas['trace_id'][0]]
                                ) - trace_ids - {0, ''}
            trace_ids |= new_trace_ids
            new_x_request_ids = set([dataframe_flowmetas['x_request_id'][0]]
                                    ) - x_request_ids - {0, ''}
            x_request_ids |= new_x_request_ids

            # L7 Flow ID信息
            l7_flow_ids |= set(dataframe_flowmetas['_id'])

            len_of_flows = len(l7_flow_ids)
            if new_trace_ids:
                trace_id_flows = await self.query_flowmetas(
                    time_filter, ' OR '.join([
                        "trace_id='{ntid}'".format(ntid=ntid)
                        for ntid in new_trace_ids
                    ])
                )
                if type(trace_id_flows) == DataFrame:
                    trace_id_flows["related_type"] = RELATED_TYPE_TRACE_ID
                    dataframe_flowmetas = pd.concat([
                        dataframe_flowmetas, trace_id_flows
                    ], join="outer", ignore_index=True)
            if new_x_request_ids:
                x_request_id_flows = await self.query_flowmetas(
                    time_filter, ' OR '.join([
                        "x_request_id='{nxrid}'".format(nxrid=nxrid)
                        for nxrid in new_x_request_ids
                    ])
                )
                if type(x_request_id_flows) == DataFrame:
                    x_request_id_flows["related_type"
                                       ] = RELATED_TYPE_X_REQUEST_ID
                    dataframe_flowmetas = pd.concat([
                        dataframe_flowmetas, x_request_id_flows
                    ], join="outer", ignore_index=True)
            if new_syscall_metas:
                syscall_flows = await self.query_flowmetas(
                    time_filter, ' OR '.join([
                        L7SyscallMeta(nsm).to_sql_filter()
                        for nsm in new_syscall_metas
                    ])
                )
                if type(syscall_flows) == DataFrame:
                    syscall_flows["related_type"] = RELATED_TYPE_SYSCALL
                    dataframe_flowmetas = pd.concat([
                        dataframe_flowmetas, syscall_flows
                    ], join="outer", ignore_index=True)
            if new_network_metas:
                network_flows = await self.query_flowmetas(
                    time_filter, ' OR '.join([
                        L7NetworkMeta(nnm).to_sql_filter(network_delay_us)
                        for nnm in new_network_metas
                    ])
                )
                if type(network_flows) == DataFrame:
                    network_flows["related_type"] = RELATED_TYPE_NETWORK
                    dataframe_flowmetas = pd.concat([
                        dataframe_flowmetas, network_flows
                    ], join="outer", ignore_index=True)
            if new_app_metas:
                app_flows = await self.query_flowmetas(
                    time_filter, ' OR '.join([
                        L7AppMeta(nam).to_sql_filter() for nam in new_app_metas
                    ])
                )
                if type(app_flows) == DataFrame:
                    app_flows["related_type"] = RELATED_TYPE_APP
            if len(set(dataframe_flowmetas['_id'])) - len_of_flows < 1:
                break
        if not l7_flow_ids:
            return []
        # 获取追踪到的所有应用流日志
        return_fields += RETURN_FIELDS
        l7_flows = await self.query_all_flows(
            time_filter, l7_flow_ids, RETURN_FIELDS
        )
        if type(l7_flows) != DataFrame:
            return []
        l7_flows.insert(0, "related_type", "")
        l7_flows = l7_flows.where(l7_flows.notnull(), None)
        for index in range(len(l7_flows.index)):
            l7_flows["related_type"][index] = dataframe_flowmetas.loc[
                dataframe_flowmetas["_id"] == l7_flows._id[index]
            ]["related_type"]
        # 对所有应用流日志排序
        l7_flows_merged, app_flows, unattached_flows = sort_all_flows(
            l7_flows, network_delay_us, return_fields, ntp_delay_us
        )

        return format(l7_flows_merged, unattached_flows, app_flows)

    async def query_ck(self, sql: str):
        querier = Querier(to_dataframe=True, debug=self.args.debug)
        response = await querier.exec_all_clusters(DATABASE, sql)
        '''
        database = 'flow_log'  # database
        host = '10.1.20.22'  # ck ip
        client = Client(
            host=host, port=9000, user='default', password='', database=database,
            send_receive_timeout=5
        )
        #rst = client.execute(SQL)
        rows = client.query_dataframe(sql)
        '''
        for region_name, value in response.get('regions', {}).items():
            if value == -1:
                self.failed_regions.add(region_name)
        return response

    async def query_flowmetas(
        self, time_filter: str, base_filter: str
    ) -> list:
        """找到base_filter对应的L7 Flowmeta
    
        网络流量追踪信息：
            type, req_tcp_seq, resp_tcp_seq, start_time_us, end_time_us
            通过tcp_seq及流日志的时间追踪
    
        系统调用追踪信息：
            vtap_id, syscall_trace_id_request, syscall_trace_id_response
            通过eBPF获取到的coroutine_trace_id追踪
    
        主动注入的追踪信息：
            trace_id：通过Tracing SDK主动注入的trace_id追踪
            x_request_id：通过Nginx/HAProxy/BFE等L7网关注入的requst_id追踪
        """
        sql = """
        SELECT 
        type, req_tcp_seq, resp_tcp_seq, toUnixTimestamp64Micro(start_time) AS start_time_us, toUnixTimestamp64Micro(end_time) AS end_time_us, 
        vtap_id, syscall_trace_id_request, syscall_trace_id_response, span_id, parent_span_id, 
        trace_id, x_request_id, _id, tap_side, resource_gl0_0, resource_gl0_1  
        FROM `l7_flow_log` 
        WHERE (({time_filter}) AND ({base_filter})) limit {l7_tracing_limit}
        """.format(
            time_filter=time_filter, base_filter=base_filter,
            l7_tracing_limit=config.l7_tracing_limit
        )
        response = await self.query_ck(sql)
        self.status.append("Query FlowMetas", response)
        return response['data']

    async def query_all_flows(
        self, time_filter: str, l7_flow_ids: list, return_fields: list
    ):
        """根据l7_flow_ids查询所有追踪到的应用流日志
                    if(is_ipv4, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0)) AS ip_0,
                if(is_ipv4, IPv4NumToString(ip4_1), IPv6NumToString(ip6_1)) AS ip_1,
                toUnixTimestamp64Micro(start_time) AS start_time_us,
                toUnixTimestamp64Micro(end_time) AS end_time_us,
                dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id_0))) AS epc_name_0,
                dictGet(deepflow.l3_epc_map, ('name'), (toUInt64(l3_epc_id_1))) AS epc_name_1,
                dictGet(deepflow.device_map, ('name'), (toUInt64(l3_device_type_0),toUInt64(l3_device_id_0))) AS l3_device_name_0,
                dictGet(deepflow.device_map, ('name'), (toUInt64(l3_device_type_1),toUInt64(l3_device_id_1))) AS l3_device_name_1,
                dictGet(deepflow.pod_map, ('name'), (toUInt64(pod_id_0))) AS pod_name_0,
                dictGet(deepflow.pod_map, ('name'), (toUInt64(pod_id_1))) AS pod_name_1,
                dictGet(deepflow.pod_node_map, ('name'), (toUInt64(pod_node_id_0))) AS pod_node_name_0,
                dictGet(deepflow.pod_node_map, ('name'), (toUInt64(pod_node_id_1))) AS pod_node_name_1
        """
        ids = []
        for flow_id in l7_flow_ids:
            ids.append(f"_id={flow_id}")
        fields = []
        for field in return_fields:
            if field in FIELDS_MAP:
                fields.append(FIELDS_MAP[field])
            else:
                fields.append(field)
        sql = """
        SELECT {fields} FROM `l7_flow_log` WHERE (({time_filter}) AND ({l7_flow_ids})) ORDER BY start_time_us asc
        """.format(
            time_filter=time_filter, l7_flow_ids=' OR '.join(ids),
            fields=",".join(fields)
        )
        response = await self.query_ck(sql)
        self.status.append("Query All Flows", response)
        return response["data"]


class L7AppMeta:
    """
    应用span追踪：
        span_id, parent_span_id
    """

    def __init__(self, flow_metas: Tuple):
        self.tap_side = flow_metas[0]
        self.span_id = flow_metas[1]
        self.parent_span_id = flow_metas[2]

    def __eq__(self, rhs):
        return (
            self.tap_side == rhs.tap_side and self.span_id == rhs.span_id
            and self.process_id == rhs.process_id
        )

    def to_sql_filter(self) -> str:
        sql_filters = []
        if type(self.span_id) == str and self.span_id:
            sql_filters.append(
                f"""(parent_span_id='{self.span_id}' OR span_id='{self.span_id}')"""
            )
        if type(self.parent_span_id) == str and self.parent_span_id:
            sql_filters.append(
                f"""(span_id='{self.parent_span_id}' OR parent_span_id='{self.parent_span_id}')"""
            )
        if not sql_filters:
            return '1!=1'
        return '(' + ' OR '.join(sql_filters) + ')'


class L7NetworkMeta:
    """
    网络流量追踪信息:
        req_tcp_seq, resp_tcp_seq, start_time_us, end_time_us
    """

    def __init__(self, flow_metas: Tuple):
        self.type = flow_metas[0]
        self.req_tcp_seq = flow_metas[1]
        self.resp_tcp_seq = flow_metas[2]
        self.start_time_us = flow_metas[3]
        self.end_time_us = flow_metas[4]

    def __eq__(self, rhs):
        return (
            self.type == rhs.type and self.req_tcp_seq == rhs.req_tcp_seq
            and self.resp_tcp_seq == rhs.resp_tcp_seq
        )

    def to_sql_filter(self, network_delay_us: int) -> str:
        # 返回空时需要忽略此条件
        # 由于会话可能没有合并，有一侧的seq可以是零（数据不会存在两侧同时为0的情况）
        # 考虑到网络传输时延，时间需要增加一个delay
        sql_filters = []
        if self.type != L7_FLOW_TYPE_RESPONSE and self.req_tcp_seq > 0:
            sql_filters.append(
                """(req_tcp_seq={req_tcp_seq} AND start_time_us>={min_start_time} AND start_time_us<={max_start_time})"""
                .format(
                    req_tcp_seq=self.req_tcp_seq,
                    min_start_time=self.start_time_us - network_delay_us,
                    max_start_time=self.start_time_us + network_delay_us
                )
            )
        if self.type != L7_FLOW_TYPE_REQUEST and self.resp_tcp_seq > 0:
            sql_filters.append(
                """(resp_tcp_seq={resp_tcp_seq} AND end_time_us>={min_end_time} AND end_time_us<={max_end_time})"""
                .format(
                    resp_tcp_seq=self.resp_tcp_seq,
                    min_end_time=self.end_time_us - network_delay_us,
                    max_end_time=self.end_time_us + network_delay_us
                )
            )
        if not sql_filters:
            return '1!=1'
        return '(' + ' OR '.join(
            sql_filters
        ) + ' AND (resp_tcp_seq!=0 OR req_tcp_seq!=0))'


class L7SyscallMeta:
    """
    系统调用追踪信息:
        vtap_id, syscall_trace_id_request, syscall_trace_id_response
    """

    def __init__(self, flowmetas: Tuple):
        self.vtap_id = flowmetas[0]
        self.syscall_trace_id_request = flowmetas[1]
        self.syscall_trace_id_response = flowmetas[2]
        self.span_id = flowmetas[3]
        self.x_request_id = flowmetas[4]

    def __eq__(self, rhs):
        return (
            self.vtap_id == rhs.vtap_id
            and self.syscall_trace_id_request == rhs.syscall_trace_id_request
            and self.syscall_trace_id_response == rhs.syscall_trace_id_response
        )

    def to_sql_filter(self) -> str:
        # 返回空时需要忽略此条件
        sql_filters = []
        if self.syscall_trace_id_request > 0:
            sql_filters.append(
                'syscall_trace_id_request={syscall_trace_id_request} OR syscall_trace_id_response={syscall_trace_id_request}'
                .format(
                    syscall_trace_id_request=self.syscall_trace_id_request
                )
            )
        if self.syscall_trace_id_response > 0:
            sql_filters.append(
                'syscall_trace_id_request={syscall_trace_id_response} OR syscall_trace_id_response={syscall_trace_id_response}'
                .format(
                    syscall_trace_id_response=self.syscall_trace_id_response
                )
            )
        if not sql_filters:
            return '1!=1'
        sql = f"vtap_id={self.vtap_id} AND ({' OR '.join(sql_filters)})"
        if type(self.span_id) == str and self.span_id:
            sql += f" AND span_id='{self.span_id}'"
        if type(self.x_request_id) == str and self.x_request_id:
            sql += f" AND x_request_id='{self.x_request_id}'"
        return f"({sql})"


class Service:

    def __init__(self, vtap_id: int, process_id: int):
        self.vtap_id = vtap_id
        self.process_id = process_id

        self.direct_flows = []
        # 一个flow_trace是一个flow数组，这组flow是同一个应用请求在网络中传输时的多次采集
        self.traces_of_direct_flows = []
        self.app_flow_of_direct_flows = []
        self.unattached_flows = dict()
        self.subnet_id = None
        self.subnet = None
        self.ip = None
        self.resource_gl2_type = None
        self.resource_gl2_id = None
        self.resource_gl2 = None
        self.process_kname = None
        self.start_time_us = 0
        self.end_time_us = 0
        self.level = -1

    def get_direct_flow_head(self, index):
        if self.traces_of_direct_flows[index]:
            if self.direct_flows[index]['tap_side'] == TAP_SIDE_SERVER_PROCESS:
                return self.traces_of_direct_flows[index][0]
            else:
                return self.traces_of_direct_flows[index][-1]
        else:
            return self.direct_flows[index]

    def connect(self, index, flow):
        if self.traces_of_direct_flows[index]:
            _set_parent(self.traces_of_direct_flows[index][0], flow)
        else:
            _set_parent(self.direct_flows[index], flow)

    def parent_set(self):
        # 网络span排序
        self.trace_sorted()
        # 有s-p
        if self.direct_flows[0]['tap_side'] == TAP_SIDE_SERVER_PROCESS:
            for i, direct_flow in enumerate(self.direct_flows[1:]):
                if not direct_flow.get('parent_id'):
                    # c-p的parent设置为s-p
                    _set_parent(direct_flow, self.direct_flows[0])
                for j, trace in enumerate(self.traces_of_direct_flows[i + 1]):
                    if j == 0:
                        # 第一个trace的parent为c-p
                        _set_parent(trace, direct_flow)
                    else:
                        # trace的parent为前一个trace
                        _set_parent(
                            trace, self.traces_of_direct_flows[i + 1][j - 1]
                        )
            # s-p有trace
            if self.traces_of_direct_flows[0]:
                # s-p的parent为trace的最后一个
                _set_parent(
                    self.direct_flows[0], self.traces_of_direct_flows[0][-1]
                )
                if self.traces_of_direct_flows[0][0].get('parent_id', -1) < 0:
                    # s-p的第一个trace的parent设置为-1
                    self.traces_of_direct_flows[0][0]['parent_id'] = -1
                for i, trace in enumerate(self.traces_of_direct_flows[0][1:]):
                    # 除了第一个外的每个trace的parent都是前一个trace
                    _set_parent(
                        trace, self.traces_of_direct_flows[0][i - 1 + 1]
                    )
            else:
                # s-p没有trace则parent设为-1
                if self.direct_flows[0].get('parent_id', -1) < 0:
                    self.direct_flows[0]['parent_id'] = -1
        else:
            # 只有c-p
            for i, direct_flow in enumerate(self.direct_flows):
                # 所有c-p的parent设为-1
                if not direct_flow.get('parent_id'):
                    self.direct_flows[i]['parent_id'] = -1
                for j, trace in enumerate(self.traces_of_direct_flows[i]):
                    if j == 0:
                        # 第一条trace的parent为c-p
                        _set_parent(trace, direct_flow)
                    else:
                        # 每一条trace的parent为前一条trace
                        _set_parent(
                            trace, self.traces_of_direct_flows[i][j - 1]
                        )

    def trace_sorted(self):
        """
        对网络span进行排序，排序规则：
        1. 按照TAP_SIDE_RANKS进行排序
        2. 对Local和rest就近（比较采集器）排到其他位置附近（按时间排）
        """
        for index, traces in enumerate(self.traces_of_direct_flows):
            local_rest_traces = []
            sorted_traces = []
            for trace in traces:
                if trace['tap_side'] in [const.TAP_SIDE_LOCAL, const.TAP_SIDE_REST]:
                    local_rest_traces.append(trace)
                else:
                    sorted_traces.append(trace)
            sorted_traces = sorted(
                sorted_traces, key=lambda x: const.TAP_SIDE_RANKS.get(x['tap_side'])
            )
            for trace in local_rest_traces:
                vtap_index = -1
                for i, sorted_trace in enumerate(sorted_traces):
                    if vtap_index > 0 and sorted_trace['vtap_id'] != trace[
                        'vtap_id']:
                        break
                    if sorted_trace['vtap_id'] == trace['vtap_id']:
                        if sorted_trace['start_time_us'] < trace[
                            'start_time_us']:
                            vtap_index = i + 1
                        elif vtap_index == -1:
                            vtap_index = i
                if vtap_index >= 0:
                    sorted_traces.insert(vtap_index, trace)
                else:
                    for i, sorted_trace in enumerate(sorted_traces):
                        if trace['start_time_us'] < sorted_trace[
                            'start_time_us']:
                            sorted_traces.insert(i, trace)
                            break
            self.traces_of_direct_flows[index] = sorted_traces

    def check_client_process_flow(self, flow: dict):
        """检查该flow是否与service有关联关系，s-p的时间范围需要覆盖c-p，否则拆分为两个service"""
        if self.process_id != flow["process_id_0"] \
            or self.vtap_id != flow["vtap_id"]:
            return False
        if self.start_time_us > flow["start_time_us"] \
            or self.end_time_us < flow["end_time_us"]:
            return False
        return True

    def add_direct_flow(self, flow: dict):
        """direct_flow是指该服务直接接收到的，或直接发出的flow"""
        #assert (
        #    self.vtap_id == flow.get('vtap_id')
        #    and self.process_id == flow.get('process_id')
        #)
        if flow['tap_side'] == TAP_SIDE_SERVER_PROCESS:
            self.start_time_us = flow["start_time_us"]
            self.end_time_us = flow["end_time_us"]
        for key in [
            'subnet_id', 'subnet', 'ip', 'resource_gl2_type',
            'resource_gl2_id', 'resource_gl2', 'process_kname',
        ]:
            if getattr(self, key):
                continue
            if flow['tap_side'] == TAP_SIDE_CLIENT_PROCESS:
                direction_key = key + "_0"
            elif flow['tap_side'] == TAP_SIDE_SERVER_PROCESS:
                direction_key = key + "_1"
            setattr(self, key, flow[direction_key])
        self.direct_flows.append(flow)
        self.traces_of_direct_flows.append([])

    def attach_app_flow(self, flow: dict):
        if flow["tap_side"] not in [TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP]:
            return
        for direct_flow in self.direct_flows:
            if direct_flow["span_id"] and direct_flow["span_id"] == flow[
                "span_id"]:
                if direct_flow["tap_side"] == TAP_SIDE_CLIENT_PROCESS:
                    _set_parent(direct_flow, flow)
                    flow["service"] = self
                else:
                    _set_parent(flow, direct_flow)
                    flow["service"] = self

    def attach_indirect_flow(self, flow: dict, network_delay_us: int):
        """将一个flow附加到direct_flow上，附加的前提是这两个flow拥有相同的网络流量追踪信息"""
        if flow["tap_side"] in [
            TAP_SIDE_CLIENT_PROCESS, TAP_SIDE_SERVER_PROCESS,
            TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP
        ]:
            return
        for index in range(len(self.direct_flows)):
            direct_flow = self.direct_flows[index]
            if (
                flow['type'] != direct_flow['type']
                and flow['type'] != L7_FLOW_TYPE_SESSION
                and direct_flow['type'] != L7_FLOW_TYPE_SESSION
            ):
                # 如果两个flow都是单向的，且是不同方向的，跳过
                continue
            is_indirect = True
            for key in MERGE_KEYS:
                if _get_df_key(flow, key) != _get_df_key(direct_flow, key):
                    is_indirect = False
                    break
            if not is_indirect:
                continue
            if (
                # 请求方向TCP SEQ无需比较（无请求方向的信息）、或相等
                flow['type'] == L7_FLOW_TYPE_RESPONSE
                or direct_flow['type'] == L7_FLOW_TYPE_RESPONSE or (
                    flow['req_tcp_seq'] == direct_flow['req_tcp_seq'] and
                    abs(flow['start_time_us'] - direct_flow['start_time_us']) <
                    network_delay_us
                )
            ) and (
                # 响应方向TCP SEQ无需比较（无请求方向的信息）、或相等
                flow['type'] == L7_FLOW_TYPE_REQUEST
                or direct_flow['type'] == L7_FLOW_TYPE_REQUEST or (
                    flow['resp_tcp_seq'] == direct_flow['resp_tcp_seq']
                    and abs(flow['end_time_us'] - direct_flow['end_time_us']) <
                    network_delay_us
                )
            ):
                self.traces_of_direct_flows[index].append(flow)
                return
        self.unattached_flows[flow['flow_id']] = flow

    def sort_flow_traces(self):
        # assert len(self.direct_flows) > 0

        index = [0] * len(self.direct_flows)
        for i in range(len(index)):
            index[i] = i
        index = sorted(
            index,
            # 按统计位置s-p优先于c-p排序
            key=lambda i: self.direct_flows[i]['tap_side'],
            reverse=True
        )
        direct_flow = [None] * len(index)
        traces_of_direct_flows = [None] * len(index)
        for x, y in enumerate(index):
            direct_flow[x] = self.direct_flows[y]
            traces_of_direct_flows[x] = self.traces_of_direct_flows[y]
        self.direct_flows = direct_flow
        self.traces_of_direct_flows = traces_of_direct_flows

        # 同一个应用请求的多个Flow Trace按时间先后排序，并记录当前服务的最小时间
        self.min_start_time_us = self.direct_flows[0]['start_time_us']
        for i in range(len(index)):
            self.traces_of_direct_flows[i] = sorted(
                self.traces_of_direct_flows[i],
                # 按时间先后排序
                key=lambda f: f['start_time_us']
            )
            if self.traces_of_direct_flows[i]:
                if self.min_start_time_us > self.traces_of_direct_flows[i][0][
                    'start_time_us']:
                    self.min_start_time_us = self.traces_of_direct_flows[i][0][
                        'start_time_us']

        # 记录当前服务的入向和出向请求中的Flow uid等信息，便于后续对所有服务进行排序
        self.incoming_flow_uids = set()
        self.outgoing_flow_uids = set()
        self.incoming_flow_process_req_tcp_seqs = set()
        self.outgoing_flow_process_req_tcp_seqs = set()
        self.incoming_flow_process_resp_tcp_seqs = set()
        self.outgoing_flow_process_resp_tcp_seqs = set()
        for f in self.direct_flows:
            tap_side = f['tap_side']
            if tap_side == TAP_SIDE_SERVER_PROCESS:
                if f['req_tcp_seq']:
                    self.incoming_flow_process_req_tcp_seqs.add(
                        f['req_tcp_seq']
                    )
                if f['resp_tcp_seq']:
                    self.incoming_flow_process_resp_tcp_seqs.add(
                        f['resp_tcp_seq']
                    )
            else:
                if f['req_tcp_seq']:
                    self.outgoing_flow_process_req_tcp_seqs.add(
                        f['req_tcp_seq']
                    )
                if f['resp_tcp_seq']:
                    self.outgoing_flow_process_resp_tcp_seqs.add(
                        f['resp_tcp_seq']
                    )
        for i in range(len(self.traces_of_direct_flows)):
            traces = self.traces_of_direct_flows[i]
            tap_side = self.direct_flows[i]['tap_side']
            for f in traces:
                if tap_side == TAP_SIDE_SERVER_PROCESS:
                    self.incoming_flow_uids.add(f['_uid'])
                else:
                    self.outgoing_flow_uids.add(f['_uid'])


def merge_flow(flows: list, flow: dict) -> bool:
    """
    只有一个请求和一个响应能合并，不能合并多个请求或多个响应；
    按如下策略合并：
    按start_time递增的顺序从前向后扫描，每发现一个请求，都找一个它后面离他最近的响应。
    例如：请求1、请求2、响应1、响应2
    则请求1和响应1配队，请求2和响应2配队
    """
    if flow['type'] == L7_FLOW_TYPE_SESSION \
        and flow['tap_side'] not in [TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS]:
        return False
    # vtap_id, l7_protocol, flow_id, request_id
    for i in range(len(flows)):
        if flow['_id'] == flows[i]['_id']:
            continue
        if flow['flow_id'] != flows[i]['flow_id']:
            continue
        if flows[i]['tap_side'] not in [
            TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ]:
            if flows[i]['type'] == L7_FLOW_TYPE_SESSION:
                continue
            # 每条flow的_id最多只有一来一回两条
            if len(flows[i]['_id']) > 1 or flow["type"] == flows[i]["type"]:
                continue
        equal = True
        request_flow = None
        response_flow = None
        if flows[i]['type'] == L7_FLOW_TYPE_REQUEST:
            request_flow = flows[i]
            response_flow = flow
        elif flows[i]['type'] == L7_FLOW_TYPE_RESPONSE:
            request_flow = flow
            response_flow = flows[i]
        else:
            if flow['type'] == L7_FLOW_TYPE_REQUEST:
                request_flow = flow
                response_flow = flows[i]
            elif flow['type'] == L7_FLOW_TYPE_RESPONSE:
                request_flow = flows[i]
                response_flow = flow
            else:
                continue
        if not request_flow or not response_flow:
            continue
        for key in [
            'vtap_id', 'tap_port', 'tap_port_type', 'l7_protocol',
            'request_id', 'tap_side'
        ]:
            if _get_df_key(request_flow,
                           key) != _get_df_key(response_flow, key):
                equal = False
                break
        # 请求的时间必须比响应的时间大
        if request_flow['start_time_us'] > response_flow['end_time_us']:
            equal = False
        if request_flow['tap_side'] in [
            TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ]:
            # 应用span syscall_cap_seq判断合并
            if request_flow['syscall_cap_seq_0'] + 1 != response_flow[
                'syscall_cap_seq_1']:
                equal = False
        if equal:  # 合并字段
            # FIXME 确认要合并哪些字段

            flows[i]['_id'].extend(flow['_id'])
            flows[i]['resource_gl0_0'] = flow['resource_gl0_0']
            flows[i]['resource_gl0_1'] = flow['resource_gl0_1']
            for key in MERGE_KEYS:
                if key in MERGE_KEY_REQUEST:
                    if flow['type'] in [
                        L7_FLOW_TYPE_REQUEST, L7_FLOW_TYPE_SESSION
                    ]:
                        flows[i][key] = flow[key]
                elif key in MERGE_KEY_RESPONSE:
                    if flow['type'] in [
                        L7_FLOW_TYPE_RESPONSE, L7_FLOW_TYPE_SESSION
                    ]:
                        flows[i][key] = flow[key]
                else:
                    if not flows[i][key]:
                        flows[i][key] = flow[key]
            if flow['type'] == L7_FLOW_TYPE_REQUEST:
                if flow['start_time_us'] < flows[i]['start_time_us']:
                    flows[i]['start_time_us'] = flow['start_time_us']
                else:
                    flows[i]['req_tcp_seq'] = flow['req_tcp_seq']
                flows[i]['syscall_cap_seq_0'] = flow['syscall_cap_seq_0']
            else:
                if flow['end_time_us'] > flows[i]['end_time_us']:
                    flows[i]['end_time_us'] = flow['end_time_us']
                    flows[i]['resp_tcp_seq'] = flow['resp_tcp_seq']
                flows[i]['syscall_cap_seq_1'] = flow['syscall_cap_seq_1']
            # request response合并后type改为session
            if flow['type'] + flows[i]['type'] == 1:
                flows[i]['type'] = 2
            flows[i]['type'] = max(flows[i]['type'], flow['type'])
            return True

    return False


def sort_all_flows(
    dataframe_flows: DataFrame, network_delay_us: int, return_fields: list,
    ntp_delay_us: int
) -> list:
    """对应用流日志排序，用于绘制火焰图。

    1. 根据系统调用追踪信息追踪：
          1 -> +-----+
               |     | -> 2
               |     | <- 2
               | svc |
               |     | -> 3
               |     ! <- 3
          1 <- +-----+
       上图中的服务进程svc在接受请求1以后，向下游继续请求了2、3，他们之间的关系是：
          syscall_trace_id_request_1  = syscall_trace_id_request_2
          syscall_trace_id_response_2 = syscall_trace_id_request_3
          syscall_trace_id_response_3 = syscall_trace_id_response_1
       上述规律可用于追踪系统调用追踪信息发现的流日志。

    2. 根据主动注入的追踪信息追踪：
       主要的原理是通过x_request_id、span_id匹配追踪，这些信息穿越L7网关时保持不变。

    3. 根据网络流量追踪信息追踪：
       主要的原理是通过TCP SEQ匹配追踪，这些信息穿越L2-L4网元时保持不变。

    4. 融合1-3的结果，并将2和3中的结果合并到1中
    """
    flows = []
    # 按start_time升序，用于merge_flow
    dict_flows = dataframe_flows.sort_values(
        by=["start_time_us"], ascending=True
    ).to_dict("list")
    for index in range(len(dataframe_flows.index)):
        flow = {}
        for key in return_fields:
            key = key.strip("'")
            if key == '_id':  # 流合并后会对应多条记录
                flow[key] = [dict_flows[key][index]]
            else:
                flow[key] = dict_flows[key][index]
        if merge_flow(flows, flow):  # 合并单向Flow为会话
            continue
        # assert '_uid' not in flow
        flow['_uid'] = index
        flows.append(flow)
    flowcount = len(flows)
    for i, flow in enumerate(reversed(flows)):
        # 单向的c-p和s-p进行第二轮merge
        if len(flow['_id']) > 1 or flow['tap_side'] not in [
            TAP_SIDE_SERVER_PROCESS, TAP_SIDE_CLIENT_PROCESS
        ]:
            continue
        if merge_flow(flows, flow):
            del flows[flowcount - i - 1]
    for flow in flows:
        flow['duration'] = flow['end_time_us'] - flow['start_time_us']

    # 从Flow中提取Service：一个<vtap_id, local_process_id>二元组认为是一个Service。
    service_map = defaultdict(Service)
    for flow in flows:
        if flow['tap_side'] != TAP_SIDE_SERVER_PROCESS:
            continue
        local_process_id = flow['process_id_1']
        vtap_id = flow['vtap_id']
        if (vtap_id, local_process_id, 0) not in service_map:
            service = Service(vtap_id, local_process_id)
            service_map[(vtap_id, local_process_id, 0)] = service
            # Service直接接收或发送的Flows_
            service.add_direct_flow(flow)
        else:
            index = 0
            for key in service_map.keys():
                if key[0] == vtap_id and key[1] == local_process_id:
                    index += 1
            service = Service(vtap_id, local_process_id)
            service_map[(vtap_id, local_process_id, index)] = service
            service.add_direct_flow(flow)

    for flow in flows:
        if flow['tap_side'] != TAP_SIDE_CLIENT_PROCESS:
            continue
        local_process_id = flow['process_id_0']
        vtap_id = flow['vtap_id']
        index = 0
        max_start_time_service = None
        if (vtap_id, local_process_id, 0) in service_map:
            for key, service in service_map.items():
                if key[0] == vtap_id and key[1] == local_process_id:
                    index += 1
                    if service.check_client_process_flow(flow):
                        if not max_start_time_service:
                            max_start_time_service = service
                        else:
                            if service.start_time_us > max_start_time_service.start_time_us:
                                max_start_time_service = service
            if max_start_time_service:
                max_start_time_service.add_direct_flow(flow)
                continue
        # 没有attach到service上的flow生成一个新的service
        service = Service(vtap_id, local_process_id)
        service_map[(vtap_id, local_process_id, index)] = service
        # Service直接接收或发送的Flow
        service.add_direct_flow(flow)

    if not service_map:
        return [], []

    # 将direct_flow在网络中的Trace作为indirect_flow挂到Service上
    # 将应用span挂到Service上
    app_flows = []
    for flow in flows:
        if flow['tap_side'] in [TAP_SIDE_CLIENT_APP, TAP_SIDE_SERVER_APP]:
            app_flows.append(flow)
            continue
        for service_key, service in service_map.items():
            service.attach_indirect_flow(flow, network_delay_us)

    for index, app_flow in enumerate(app_flows):
        for service_key, service in service_map.items():
            if service.attach_app_flow(app_flow):
                break

    unattached_flow_ids = set()
    unattached_flow_map = dict()
    for _, service in service_map.items():
        unattached_flow_map.update(service.unattached_flows)
    for i, service in enumerate(list(service_map.values())):
        # 某一个service挂了所有flow，break
        if not service.unattached_flows:
            unattached_flow_ids = set()
            break
        # 所有service的unattached_flow取交集，得到没有挂上去的所有flow
        if i == 0:
            unattached_flow_ids = set(service.unattached_flows.keys())
        else:
            unattached_flow_ids &= set(service.unattached_flows.keys())
    unattached_flows = [
        unattached_flow_map[flow_id] for flow_id in unattached_flow_ids
    ]

    # 对service上挂的flow排序
    # 1. 同一组flow按时间排序
    # 2. 选取时间最早或最晚的作为incoming_flow
    for service_key, service in service_map.items():
        service.sort_flow_traces()
        service.parent_set()

    # 对service排序，确定上下级
    services = list(service_map.values())
    parent_sort(services)
    app_flow_sort(app_flows)
    ''' services = bfs_sort(
        services,
        lambda x, y: x.min_start_time_us - ntp_delay_us <= y.min_start_time_us
        and (
            # 1. Service A的出向flow和service B的入向flow存在交集（比较_uid），则A是B的上级
            len(x.outgoing_flow_uids & y.incoming_flow_uids) > 0 or
            # 2. Service A的出向flow和service B的入向flow的x_request_id或span_id存在交集，则A是B的上级
            len(
                x.outgoing_flow_process_req_tcp_seqs & y.
                incoming_flow_process_req_tcp_seqs
            ) > 0 or len(
                x.outgoing_flow_process_resp_tcp_seqs & y.
                incoming_flow_process_resp_tcp_seqs
            ) > 0
        ),
        lambda i, level: setattr(services[i], 'level', level)
    ) '''

    return services, app_flows, unattached_flows


def app_flow_sort(array: list):
    array.reverse()
    for flow_0 in array:
        for flow_1 in array:
            if flow_0["parent_span_id"] == flow_1["span_id"]:
                _set_parent(flow_0, flow_1)
                if flow_0.get("service",
                              None) and not flow_1.get("service", None):
                    flow_1["service"] = flow_0["service"]
                break
    for flow in array:
        if flow.get("parent_id", -1) < 0 and flow.get("service"):
            if flow["service"].direct_flows[0]["tap_side"
                                               ] == TAP_SIDE_SERVER_PROCESS:
                _set_parent(flow, flow["service"].direct_flows[0])
                continue

    array.reverse()


def parent_sort(array: list):
    for i in range(len(array)):
        for j in range(len(array)):
            if i != j and array[i].min_start_time_us - 10000 <= array[
                j].min_start_time_us + 10000:
                if len(
                    array[i].outgoing_flow_uids & array[j].incoming_flow_uids
                ) > 0:
                    for _uid in array[i].outgoing_flow_uids & array[
                        j].incoming_flow_uids:
                        # 去重，去掉s-p中重复的，因为service内部已经进行过parent关联，因此当网络span有交叠时无需关联service
                        dedup_indexs = []
                        for i, flow in enumerate(
                            array[j].traces_of_direct_flows[0]
                        ):
                            if flow['_uid'] == _uid:
                                dedup_indexs.append(i)
                        dedup_indexs.reverse()
                        for i in dedup_indexs:
                            array[j].traces_of_direct_flows[0].pop(i)
                elif len(
                    array[i].outgoing_flow_process_resp_tcp_seqs
                    & array[j].incoming_flow_process_resp_tcp_seqs
                ) > 0:
                    for resp_tcp_seq in array[
                        i].outgoing_flow_process_resp_tcp_seqs & array[
                            j].incoming_flow_process_resp_tcp_seqs:
                        for index, flow in enumerate(array[i].direct_flows):
                            if flow['resp_tcp_seq'] and flow['resp_tcp_seq'
                                                             ] == resp_tcp_seq:
                                parent_flow = array[i].get_direct_flow_head(
                                    index
                                )
                                # s-p通过resp_tcp_seq关联c-p
                                array[j].connect(0, parent_flow)
                elif len(
                    array[i].outgoing_flow_process_req_tcp_seqs
                    & array[j].incoming_flow_process_req_tcp_seqs
                ) > 0:
                    for resp_tcp_seq in array[
                        i].outgoing_flow_process_req_tcp_seqs & array[
                            j].incoming_flow_process_req_tcp_seqs:
                        for index, flow in enumerate(array[i].direct_flows):
                            if flow['req_tcp_seq'] and flow['req_tcp_seq'
                                                            ] == resp_tcp_seq:
                                parent_flow = array[i].get_direct_flow_head(
                                    index
                                )
                                # s-p通过req_tcp_seq关联c-p
                                array[j].connect(0, parent_flow)


def bfs_sort(array: list, less_then_func, level_set_func):
    """宽度优先搜索

    使用 less_then_func 作为比较函数
    使用 level_set_func 作为可选的level设置函数
    """
    # 初始化及构造邻接表
    prev_matrix = []  # 前向邻接表
    next_matrix = []  # 后向邻接表
    rest_indices = set()  # 尚未排序表项的index下标
    sorted_indices = []  # 排序后的index下标
    for i in range(len(array)):
        prev_matrix.append([])
        next_matrix.append([])
        rest_indices.add(i)
    for i in range(len(array)):
        for j in range(len(array)):
            if i != j and less_then_func(array[i], array[j]):
                prev_matrix[j].append(i)
                next_matrix[i].append(j)
    # 没有前向节点的表项认为是root
    level = 0
    next_level_indices = []
    for i in range(len(array)):
        if len(prev_matrix[i]) == 0:
            next_level_indices.append(i)
    # 从root开始宽搜
    while True:
        # 当找不到下个层级时（存在环），从环中挑选入度最小的作为下一级
        if len(next_level_indices) == 0:
            min_degree = len(array)
            min_degree_index = -1
            for i in rest_indices:
                if len(prev_matrix[i]) < min_degree:
                    min_degree = len(prev_matrix[i])
                    min_degree_index = i
            if min_degree_index == -1:
                break
            next_level_indices = [min_degree_index]
        # 宽搜
        while len(next_level_indices) > 0:
            # 设置当前层级的level
            new_next_level_indices = set()
            for i in next_level_indices:
                rest_indices.remove(i)
                sorted_indices.append(i)
                if level_set_func is not None:
                    level_set_func(i, level)
            # 从下一级开始往前再搜索一级
            for i in next_level_indices:
                for j in next_matrix[i]:
                    if j in rest_indices:
                        new_next_level_indices.add(j)
            next_level_indices = list(new_next_level_indices)
            level += 1
    # 按宽搜顺序排序后返回
    return [array[i] for i in sorted_indices]


def format(
    services: list, unattached_flows: list, app_flows: DataFrame
) -> list:
    response = {
        'services': [],
        'unattached_flows': [
            _get_flow_dict(flow) for flow in unattached_flows
        ],
        'tracing': []
    }
    metrics_map = {}
    tracing = set()
    for service in services:
        service_uid = f"{service.resource_gl2_id}-"
        if service_uid not in metrics_map:
            metrics_map[service_uid] = {
                "service_uid": service_uid,
                "service_uname": service.resource_gl2,
                "duration": 0,
            }
        else:
            for key in [
                'service_uname'
            ]:
                if metrics_map[service_uid].get(key):
                    continue
                elif getattr(service, key):
                    metrics_map[service_uid][key] = getattr(service, key)
        for index, flow in enumerate(service.direct_flows):
            metrics_map[service_uid]["duration"] += flow["duration"]
            flow['service_uid'] = service_uid
            flow['service_uname'] = service.resource_gl2
            if flow['_uid'] not in tracing:
                response["tracing"].append(_get_flow_dict(flow))
                tracing.add(flow['_uid'])
            for indirect_flow in service.traces_of_direct_flows[index]:
                if set(indirect_flow["_id"]) == set(flow["_id"]):
                    continue
                if indirect_flow["start_time_us"] < flow["start_time_us"]:
                    flow["start_time_us"] = indirect_flow["start_time_us"]
                if indirect_flow["end_time_us"] > flow["end_time_us"]:
                    flow["end_time_us"] = indirect_flow["end_time_us"]
                if indirect_flow["response_status"] > flow["response_status"]:
                    flow["response_status"] = indirect_flow["response_status"]
                if indirect_flow['_uid'] not in tracing:
                    response["tracing"].append(_get_flow_dict(indirect_flow))
                    tracing.add(indirect_flow['_uid'])
    for flow in app_flows:
        if not flow.get("service"):
            service_uid = f"-{flow['attribute.service_name']}"
            if service_uid not in metrics_map:
                metrics_map[service_uid] = {
                    "service_uid": service_uid,
                    "service_uname": flow["attribute.service_name"],
                    "duration": 0,
                }
            flow["service_uid"] = service_uid
            flow["service_uname"] = flow["attribute.service_name"]
            metrics_map[service_uid]["duration"] += flow["duration"]
        else:
            service_uid = f"{flow['service'].resource_gl2_id}-"
            flow["service_uid"] = service_uid
            flow["service_uname"] = metrics_map[service_uid]["service_uname"]
            metrics_map[service_uid]["duration"] += flow["duration"]
        response["tracing"].append(_get_flow_dict(flow))
    response["services"] = _call_metrics(metrics_map)
    return response


def _call_metrics(services: dict):
    sum_duration = 0
    response = []
    for _, service in services.items():
        sum_duration += service["duration"]
    for _, service in services.items():
        service["duration_ratio"] = service["duration_ratio"] = '%.2f' % (
            service["duration"] / sum_duration * 100
        ) if sum_duration > 0 else 0
        response.append(service)
    response = sorted(response, key=lambda x: x.get("duration"), reverse=True)
    return response


def _get_flow_dict(flow: DataFrame):
    return {
        "_ids": list(map(str, flow["_id"])),
        "related_type": flow["related_type"],
        "start_time_us": flow["start_time_us"],
        "end_time_us": flow["end_time_us"],
        "duration": flow["end_time_us"] - flow["start_time_us"],
        "tap_side": flow["tap_side"],
        "l7_protocol": flow["l7_protocol"],
        "request_type": flow["request_type"],
        "request_resource": flow["request_resource"],
        "response_status": flow["response_status"],
        "flow_id": str(flow["flow_id"]),
        "request_id": _get_df_key(flow, "request_id"),
        "x_request_id": flow["x_request_id"],
        "trace_id": flow["trace_id"],
        "span_id": flow["span_id"],
        "parent_span_id": flow["parent_span_id"],
        "req_tcp_seq": flow["req_tcp_seq"],
        "resp_tcp_seq": flow["resp_tcp_seq"],
        "syscall_trace_id_request": str(flow["syscall_trace_id_request"]),
        "syscall_trace_id_response": str(flow["syscall_trace_id_response"]),
        "syscall_cap_seq_0": flow["syscall_cap_seq_0"],
        "syscall_cap_seq_1": flow["syscall_cap_seq_1"],
        "id": flow["_uid"],
        "parent_id": flow.get("parent_id", -1),
        "process_kname": flow.get("process_kname", None),
        "process_id": flow.get("process_id", None),
        "vtap_id": flow.get("vtap_id", None),
        "service_uid": flow.get("service_uid", None),
        "service_uname": flow.get("service_uname", None),
        "tap_port": flow["tap_port"],
        "tap_port_name": flow["tap_port_name"],
        "resource_from_vtap": flow["resource_from_vtap"][2] if flow["resource_from_vtap"][0] else None,
        "resource_gl0": flow["resource_gl0_0"]
        if flow["tap_side"][0] == 'c' else flow["resource_gl0_1"]
    }


def _get_df_key(df: DataFrame, key: str):
    if type(df[key]) == float:
        if math.isnan(df[key]):
            return None
    return df[key]


def _set_parent(flow, flow_parent):
    flow['parent_id'] = flow_parent['_uid']
    flow_parent['duration'] -= (flow['end_time_us'] - flow['start_time_us'])
