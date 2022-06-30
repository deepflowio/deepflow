from schematics.models import Model
from schematics.types import IntType, StringType, BooleanType


class FlowLogL7Tracing(Model):
    time_start = IntType(
        serialized_name="TIME_START", required=True, min_value=0
    )
    time_end = IntType(serialized_name="TIME_END", required=True, min_value=0)
    database = StringType(serialized_name="DATABASE", required=True)
    table = StringType(serialized_name="TABLE", required=True)
    _id = StringType(serialized_name="_id", required=True)
    debug = BooleanType(serialized_name="DEBUG", required=False)
    max_iteration = IntType(
        serialized_name="MAX_ITERATION", required=False, min_value=1,
        default=30
    )
    network_delay_us = IntType(
        serialized_name="NETWORK_DELAY_US", required=False, min_value=1,
        default=3000000
    )
    ntp_delay_us = IntType(
        serialized_name="NTP_DELAY_US", required=False, min_value=1,
        default=10000
    )