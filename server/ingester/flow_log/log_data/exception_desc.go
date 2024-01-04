/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package log_data

var dubboExceptionDescs = []string{
	20:  "OK",
	30:  "CLIENT_TIMEOUT",
	31:  "SERVER_TIMEOUT",
	40:  "BAD_REQUEST",
	50:  "BAD_RESPONSE",
	60:  "SERVICE_NOT_FOUND",
	70:  "SERVICE_ERROR",
	80:  "SERVER_ERROR",
	90:  "CLIENT_ERROR",
	100: "SERVER_THREADPOOL_EXHAUSTED_ERROR",
}

func GetDubboExceptionDesc(errCode uint16) string {
	if int(errCode) < len(dubboExceptionDescs) {
		return dubboExceptionDescs[errCode]
	}
	return ""
}

type KafakaCode int16

const (
	UNKNOWN_SERVER_ERROR                             = -1
	NONE                                  KafakaCode = 0
	OFFSET_OUT_OF_RANGE                              = 1
	CORRUPT_MESSAGE                                  = 2
	UNKNOWN_TOPIC_OR_PARTITION                       = 3
	INVALID_FETCH_SIZE                               = 4
	LEADER_NOT_AVAILABLE                             = 5
	NOT_LEADER_OR_FOLLOWER                           = 6
	REQUEST_TIMED_OUT                                = 7
	BROKER_NOT_AVAILABLE                             = 8
	REPLICA_NOT_AVAILABLE                            = 9
	MESSAGE_TOO_LARGE                                = 10
	STALE_CONTROLLER_EPOCH                           = 11
	OFFSET_METADATA_TOO_LARGE                        = 12
	NETWORK_EXCEPTION                                = 13
	COORDINATOR_LOAD_IN_PROGRESS                     = 14
	COORDINATOR_NOT_AVAILABLE                        = 15
	NOT_COORDINATOR                                  = 16
	INVALID_TOPIC_EXCEPTION                          = 17
	RECORD_LIST_TOO_LARGE                            = 18
	NOT_ENOUGH_REPLICAS                              = 19
	NOT_ENOUGH_REPLICAS_AFTER_APPEND                 = 20
	INVALID_REQUIRED_ACKS                            = 21
	ILLEGAL_GENERATION                               = 22
	INCONSISTENT_GROUP_PROTOCOL                      = 23
	INVALID_GROUP_ID                                 = 24
	UNKNOWN_MEMBER_ID                                = 25
	INVALID_SESSION_TIMEOUT                          = 26
	REBALANCE_IN_PROGRESS                            = 27
	INVALID_COMMIT_OFFSET_SIZE                       = 28
	TOPIC_AUTHORIZATION_FAILED                       = 29
	GROUP_AUTHORIZATION_FAILED                       = 30
	CLUSTER_AUTHORIZATION_FAILED                     = 31
	INVALID_TIMESTAMP                                = 32
	UNSUPPORTED_SASL_MECHANISM                       = 33
	ILLEGAL_SASL_STATE                               = 34
	UNSUPPORTED_VERSION                              = 35
	TOPIC_ALREADY_EXISTS                             = 36
	INVALID_PARTITIONS                               = 37
	INVALID_REPLICATION_FACTOR                       = 38
	INVALID_REPLICA_ASSIGNMENT                       = 39
	INVALID_CONFIG                                   = 40
	NOT_CONTROLLER                                   = 41
	INVALID_REQUEST                                  = 42
	UNSUPPORTED_FOR_MESSAGE_FORMAT                   = 43
	POLICY_VIOLATION                                 = 44
	OUT_OF_ORDER_SEQUENCE_NUMBER                     = 45
	DUPLICATE_SEQUENCE_NUMBER                        = 46
	INVALID_PRODUCER_EPOCH                           = 47
	INVALID_TXN_STATE                                = 48
	INVALID_PRODUCER_ID_MAPPING                      = 49
	INVALID_TRANSACTION_TIMEOUT                      = 50
	CONCURRENT_TRANSACTIONS                          = 51
	TRANSACTION_COORDINATOR_FENCED                   = 52
	TRANSACTIONAL_ID_AUTHORIZATION_FAILED            = 53
	SECURITY_DISABLED                                = 54
	OPERATION_NOT_ATTEMPTED                          = 55
	KAFKA_STORAGE_ERROR                              = 56
	LOG_DIR_NOT_FOUND                                = 57
	SASL_AUTHENTICATION_FAILED                       = 58
	UNKNOWN_PRODUCER_ID                              = 59
	REASSIGNMENT_IN_PROGRESS                         = 60
	DELEGATION_TOKEN_AUTH_DISABLED                   = 61
	DELEGATION_TOKEN_NOT_FOUND                       = 62
	DELEGATION_TOKEN_OWNER_MISMATCH                  = 63
	DELEGATION_TOKEN_REQUEST_NOT_ALLOWED             = 64
	DELEGATION_TOKEN_AUTHORIZATION_FAILED            = 65
	DELEGATION_TOKEN_EXPIRED                         = 66
	INVALID_PRINCIPAL_TYPE                           = 67
	NON_EMPTY_GROUP                                  = 68
	GROUP_ID_NOT_FOUND                               = 69
	FETCH_SESSION_ID_NOT_FOUND                       = 70
	INVALID_FETCH_SESSION_EPOCH                      = 71
	LISTENER_NOT_FOUND                               = 72
	TOPIC_DELETION_DISABLED                          = 73
	FENCED_LEADER_EPOCH                              = 74
	UNKNOWN_LEADER_EPOCH                             = 75
	UNSUPPORTED_COMPRESSION_TYPE                     = 76
	STALE_BROKER_EPOCH                               = 77
	OFFSET_NOT_AVAILABLE                             = 78
	MEMBER_ID_REQUIRED                               = 79
	PREFERRED_LEADER_NOT_AVAILABLE                   = 80
	GROUP_MAX_SIZE_REACHED                           = 81
	FENCED_INSTANCE_ID                               = 82
	ELIGIBLE_LEADERS_NOT_AVAILABLE                   = 83
	ELECTION_NOT_NEEDED                              = 84
	NO_REASSIGNMENT_IN_PROGRESS                      = 85
	GROUP_SUBSCRIBED_TO_TOPIC                        = 86
	INVALID_RECORD                                   = 87
	UNSTABLE_OFFSET_COMMIT                           = 88
	THROTTLING_QUOTA_EXCEEDED                        = 89
	PRODUCER_FENCED                                  = 90
	RESOURCE_NOT_FOUND                               = 91
	DUPLICATE_RESOURCE                               = 92
	UNACCEPTABLE_CREDENTIAL                          = 93
	INCONSISTENT_VOTER_SET                           = 94
	INVALID_UPDATE_VERSION                           = 95
	FEATURE_UPDATE_FAILED                            = 96
	PRINCIPAL_DESERIALIZATION_FAILURE                = 97
	SNAPSHOT_NOT_FOUND                               = 98
	POSITION_OUT_OF_RANGE                            = 99
	UNKNOWN_TOPIC_ID                                 = 100
	DUPLICATE_BROKER_REGISTRATION                    = 101
	BROKER_ID_NOT_REGISTERED                         = 102
	INCONSISTENT_TOPIC_ID                            = 103
	INCONSISTENT_CLUSTER_ID                          = 104
	TRANSACTIONAL_ID_NOT_FOUND                       = 105
	FETCH_SESSION_TOPIC_ID_ERROR                     = 106
)

const (
	UNKNOWN_SERVER_ERROR_DESC = "The server experienced an unexpected error when processing the request."
)

var kafkaExceptionDescs = []string{
	OFFSET_OUT_OF_RANGE:                   "The requested offset is not within the range of offsets maintained by the server.",
	CORRUPT_MESSAGE:                       "This message has failed its CRC checksum, exceeds the valid size, has a null key for a compacted topic, or is otherwise corrupt.",
	UNKNOWN_TOPIC_OR_PARTITION:            "This server does not host this topic-partition.",
	INVALID_FETCH_SIZE:                    "The requested fetch size is invalid.",
	LEADER_NOT_AVAILABLE:                  "There is no leader for this topic-partition as we are in the middle of a leadership election.",
	NOT_LEADER_OR_FOLLOWER:                "For requests intended only for the leader, this error indicates that the broker is not the current leader. For requests intended for any replica, this error indicates that the broker is not a replica of the topic partition.",
	REQUEST_TIMED_OUT:                     "The request timed out.",
	BROKER_NOT_AVAILABLE:                  "The broker is not available.",
	REPLICA_NOT_AVAILABLE:                 "The replica is not available for the requested topic-partition. Produce/Fetch requests and other requests intended only for the leader or follower return NOT_LEADER_OR_FOLLOWER if the broker is not a replica of the topic-partition.",
	MESSAGE_TOO_LARGE:                     "The request included a message larger than the max message size the server will accept.",
	STALE_CONTROLLER_EPOCH:                "The controller moved to another broker.",
	OFFSET_METADATA_TOO_LARGE:             "The metadata field of the offset request was too large.",
	NETWORK_EXCEPTION:                     "The server disconnected before a response was received.",
	COORDINATOR_LOAD_IN_PROGRESS:          "The coordinator is loading and hence can't process requests.",
	COORDINATOR_NOT_AVAILABLE:             "The coordinator is not available.",
	NOT_COORDINATOR:                       "This is not the correct coordinator.",
	INVALID_TOPIC_EXCEPTION:               "The request attempted to perform an operation on an invalid topic.",
	RECORD_LIST_TOO_LARGE:                 "The request included message batch larger than the configured segment size on the server.",
	NOT_ENOUGH_REPLICAS:                   "Messages are rejected since there are fewer in-sync replicas than required.",
	NOT_ENOUGH_REPLICAS_AFTER_APPEND:      "Messages are written to the log, but to fewer in-sync replicas than required.",
	INVALID_REQUIRED_ACKS:                 "Produce request specified an invalid value for required acks.",
	ILLEGAL_GENERATION:                    "Specified group generation id is not valid.",
	INCONSISTENT_GROUP_PROTOCOL:           "The group member's supported protocols are incompatible with those of existing members or first group member tried to join with empty protocol type or empty protocol list.",
	INVALID_GROUP_ID:                      "The configured groupId is invalid.",
	UNKNOWN_MEMBER_ID:                     "The coordinator is not aware of this member.",
	INVALID_SESSION_TIMEOUT:               "The session timeout is not within the range allowed by the broker (as configured by group.min.session.timeout.ms and group.max.session.timeout.ms).",
	REBALANCE_IN_PROGRESS:                 "The group is rebalancing, so a rejoin is needed.",
	INVALID_COMMIT_OFFSET_SIZE:            "The committing offset data size is not valid.",
	TOPIC_AUTHORIZATION_FAILED:            "Topic authorization failed.",
	GROUP_AUTHORIZATION_FAILED:            "Group authorization failed.",
	CLUSTER_AUTHORIZATION_FAILED:          "Cluster authorization failed.",
	INVALID_TIMESTAMP:                     "The timestamp of the message is out of acceptable range.",
	UNSUPPORTED_SASL_MECHANISM:            "The broker does not support the requested SASL mechanism.",
	ILLEGAL_SASL_STATE:                    "Request is not valid given the current SASL state.",
	UNSUPPORTED_VERSION:                   "The version of API is not supported.",
	TOPIC_ALREADY_EXISTS:                  "Topic with this name already exists.",
	INVALID_PARTITIONS:                    "Number of partitions is below 1.",
	INVALID_REPLICATION_FACTOR:            "Replication factor is below 1 or larger than the number of available brokers.",
	INVALID_REPLICA_ASSIGNMENT:            "Replica assignment is invalid.",
	INVALID_CONFIG:                        "Configuration is invalid.",
	NOT_CONTROLLER:                        "This is not the correct controller for this cluster.",
	INVALID_REQUEST:                       "This most likely occurs because of a request being malformed by the client library or the message was sent to an incompatible broker. See the broker logs for more details.",
	UNSUPPORTED_FOR_MESSAGE_FORMAT:        "The message format version on the broker does not support the request.",
	POLICY_VIOLATION:                      "Request parameters do not satisfy the configured policy.",
	OUT_OF_ORDER_SEQUENCE_NUMBER:          "The broker received an out of order sequence number.",
	DUPLICATE_SEQUENCE_NUMBER:             "The broker received a duplicate sequence number.",
	INVALID_PRODUCER_EPOCH:                "Producer attempted to produce with an old epoch.",
	INVALID_TXN_STATE:                     "The producer attempted a transactional operation in an invalid state.",
	INVALID_PRODUCER_ID_MAPPING:           "The producer attempted to use a producer id which is not currently assigned to its transactional id.",
	INVALID_TRANSACTION_TIMEOUT:           "The transaction timeout is larger than the maximum value allowed by the broker (as configured by transaction.max.timeout.ms).",
	CONCURRENT_TRANSACTIONS:               "The producer attempted to update a transaction while another concurrent operation on the same transaction was ongoing.",
	TRANSACTION_COORDINATOR_FENCED:        "Indicates that the transaction coordinator sending a WriteTxnMarker is no longer the current coordinator for a given producer.",
	TRANSACTIONAL_ID_AUTHORIZATION_FAILED: "Transactional Id authorization failed.",
	SECURITY_DISABLED:                     "Security features are disabled.",
	OPERATION_NOT_ATTEMPTED:               "The broker did not attempt to execute this operation. This may happen for batched RPCs where some operations in the batch failed, causing the broker to respond without trying the rest.",
	KAFKA_STORAGE_ERROR:                   "Disk error when trying to access log file on the disk.",
	LOG_DIR_NOT_FOUND:                     "The user-specified log directory is not found in the broker config.",
	SASL_AUTHENTICATION_FAILED:            "SASL Authentication failed.",
	UNKNOWN_PRODUCER_ID:                   "This exception is raised by the broker if it could not locate the producer metadata associated with the producerId in question. This could happen if, for instance, the producer's records were deleted because their retention time had elapsed. Once the last records of the producerId are removed, the producer's metadata is removed from the broker, and future appends by the producer will return this exception.",
	REASSIGNMENT_IN_PROGRESS:              "A partition reassignment is in progress.",
	DELEGATION_TOKEN_AUTH_DISABLED:        "Delegation Token feature is not enabled.",
	DELEGATION_TOKEN_NOT_FOUND:            "Delegation Token is not found on server.",
	DELEGATION_TOKEN_OWNER_MISMATCH:       "Specified Principal is not valid Owner/Renewer.",
	DELEGATION_TOKEN_REQUEST_NOT_ALLOWED:  "Delegation Token requests are not allowed on PLAINTEXT/1-way SSL channels and on delegation token authenticated channels.",
	DELEGATION_TOKEN_AUTHORIZATION_FAILED: "Delegation Token authorization failed.",
	DELEGATION_TOKEN_EXPIRED:              "Delegation Token is expired.",
	INVALID_PRINCIPAL_TYPE:                "Supplied principalType is not supported.",
	NON_EMPTY_GROUP:                       "The group is not empty.",
	GROUP_ID_NOT_FOUND:                    "The group id does not exist.",
	FETCH_SESSION_ID_NOT_FOUND:            "The fetch session ID was not found.",
	INVALID_FETCH_SESSION_EPOCH:           "The fetch session epoch is invalid.",
	LISTENER_NOT_FOUND:                    "There is no listener on the leader broker that matches the listener on which metadata request was processed.",
	TOPIC_DELETION_DISABLED:               "Topic deletion is disabled.",
	FENCED_LEADER_EPOCH:                   "The leader epoch in the request is older than the epoch on the broker.",
	UNKNOWN_LEADER_EPOCH:                  "The leader epoch in the request is newer than the epoch on the broker.",
	UNSUPPORTED_COMPRESSION_TYPE:          "The requesting client does not support the compression type of given partition.",
	STALE_BROKER_EPOCH:                    "Broker epoch has changed.",
	OFFSET_NOT_AVAILABLE:                  "The leader high watermark has not caught up from a recent leader election so the offsets cannot be guaranteed to be monotonically increasing.",
	MEMBER_ID_REQUIRED:                    "The group member needs to have a valid member id before actually entering a consumer group.",
	PREFERRED_LEADER_NOT_AVAILABLE:        "The preferred leader was not available.",
	GROUP_MAX_SIZE_REACHED:                "The consumer group has reached its max size.",
	FENCED_INSTANCE_ID:                    "The broker rejected this static consumer since another consumer with the same group.instance.id has registered with a different member.id.",
	ELIGIBLE_LEADERS_NOT_AVAILABLE:        "Eligible topic partition leaders are not available.",
	ELECTION_NOT_NEEDED:                   "Leader election not needed for topic partition.",
	NO_REASSIGNMENT_IN_PROGRESS:           "No partition reassignment is in progress.",
	GROUP_SUBSCRIBED_TO_TOPIC:             "Deleting offsets of a topic is forbidden while the consumer group is actively subscribed to it.",
	INVALID_RECORD:                        "This record has failed the validation on broker and hence will be rejected.",
	UNSTABLE_OFFSET_COMMIT:                "There are unstable offsets that need to be cleared.",
	THROTTLING_QUOTA_EXCEEDED:             "The throttling quota has been exceeded.",
	PRODUCER_FENCED:                       "There is a newer producer with the same transactionalId which fences the current one.",
	RESOURCE_NOT_FOUND:                    "A request illegally referred to a resource that does not exist.",
	DUPLICATE_RESOURCE:                    "A request illegally referred to the same resource twice.",
	UNACCEPTABLE_CREDENTIAL:               "Requested credential would not meet criteria for acceptability.",
	INCONSISTENT_VOTER_SET:                "Indicates that the either the sender or recipient of a voter-only request is not one of the expected voters.",
	INVALID_UPDATE_VERSION:                "The given update version was invalid.",
	FEATURE_UPDATE_FAILED:                 "Unable to update finalized features due to an unexpected server error.",
	PRINCIPAL_DESERIALIZATION_FAILURE:     "Request principal deserialization failed during forwarding. This indicates an internal error on the broker cluster security setup.",
	SNAPSHOT_NOT_FOUND:                    "Requested snapshot was not found.",
	POSITION_OUT_OF_RANGE:                 "Requested position is not greater than or equal to zero, and less than the size of the snapshot.",
	UNKNOWN_TOPIC_ID:                      "This server does not host this topic ID.",
	DUPLICATE_BROKER_REGISTRATION:         "This broker ID is already in use.",
	BROKER_ID_NOT_REGISTERED:              "The given broker ID was not registered.",
	INCONSISTENT_TOPIC_ID:                 "The log's topic ID did not match the topic ID in the request.",
	INCONSISTENT_CLUSTER_ID:               "The clusterId in the request does not match that found on the server.",
	TRANSACTIONAL_ID_NOT_FOUND:            "The transactionalId could not be found.",
	FETCH_SESSION_TOPIC_ID_ERROR:          "The fetch session encountered inconsistent topic ID usage",
}

func GetKafkaExceptionDesc(errCode int16) string {
	if errCode == UNKNOWN_SERVER_ERROR {
		return UNKNOWN_SERVER_ERROR_DESC
	}
	if errCode > 0 && int(errCode) < len(kafkaExceptionDescs) {
		return kafkaExceptionDescs[errCode]
	}
	return ""
}

var httpExceptionDescs = []string{
	100: "Continue",
	101: "Switching Protocols",
	102: "Processing (WebDAV; RFC 2518)",
	103: "Early Hints (RFC 8297)",
	200: "OK",
	201: "Created",
	202: "Accepted",
	203: "Non-Authoritative Information (since HTTP/1.1)",
	204: "No Content",
	205: "Reset Content",
	206: "Partial Content (RFC 7233)",
	207: "Multi-Status (WebDAV; RFC 4918)",
	208: "Already Reported (WebDAV; RFC 5842)",
	226: "IM Used (RFC 3229)",
	300: "Multiple Choices",
	301: "Moved Permanently",
	302: "Found (Previously \"Moved temporarily\")",
	303: "See Other (since HTTP/1.1)",
	304: "Not Modified (RFC 7232)",
	305: "Use Proxy (since HTTP/1.1)",
	306: "Switch Proxy",
	307: "Temporary Redirect (since HTTP/1.1)",
	308: "Permanent Redirect (RFC 7538)",
	400: "Bad Request",
	401: "Unauthorized (RFC 7235)",
	402: "Payment Required",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	407: "Proxy Authentication Required (RFC 7235)",
	408: "Request Timeout",
	409: "Conflict",
	410: "Gone",
	411: "Length Required",
	412: "Precondition Failed (RFC 7232)",
	413: "Payload Too Large (RFC 7231)",
	414: "URI Too Long (RFC 7231)",
	415: "Unsupported Media Type (RFC 7231)",
	416: "Range Not Satisfiable (RFC 7233)",
	417: "Expectation Failed",
	418: "I'm a teapot (RFC 2324, RFC 7168)",
	421: "Misdirected Request (RFC 7540)",
	422: "Unprocessable Entity (WebDAV; RFC 4918)",
	423: "Locked (WebDAV; RFC 4918)",
	424: "Failed Dependency (WebDAV; RFC 4918)",
	425: "Too Early (RFC 8470)",
	426: "Upgrade Required",
	428: "Precondition Required (RFC 6585)",
	429: "Too Many Requests (RFC 6585)",
	431: "Request Header Fields Too Large (RFC 6585)",
	451: "Unavailable For Legal Reasons (RFC 7725)",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
	505: "HTTP Version Not Supported",
	506: "Variant Also Negotiates (RFC 2295)",
	507: "Insufficient Storage (WebDAV; RFC 4918)",
	508: "Loop Detected (WebDAV; RFC 5842)",
	510: "Not Extended (RFC 2774)",
	511: "Network Authentication Required (RFC 6585)",
}

func GetHTTPExceptionDesc(errCode uint16) string {
	if int(errCode) < len(httpExceptionDescs) {
		return httpExceptionDescs[errCode]
	}
	return ""
}

var dnsExceptionDescs = []string{
	0:  "No Error",
	1:  "Format Error",
	2:  "Server Failure",
	3:  "Non-Existent Domain",
	4:  "Not Implemented",
	5:  "Query Refused",
	6:  "Name Exists when it should not",
	7:  "RR Set Exists when it should not",
	8:  "RR Set that should exist does not",
	9:  "Server Not Authoritative for zone",
	10: "Name not contained in zone",
	11: "available for assignment",
	12: "available for assignment",
	13: "available for assignment",
	14: "available for assignment",
	15: "available for assignment",
	16: "Bad OPT Version [RFC 2671]; TSIG Signature Failure [RFC 2845]",
	17: "Key not recognized",
	18: "Signature out of time window",
	19: "Bad TKEY Mode",
	20: "Duplicate key name",
	21: "Algorithm not supported",
}

func GetDNSExceptionDesc(errCode uint16) string {
	if int(errCode) < len(dnsExceptionDescs) {
		return dnsExceptionDescs[errCode]
	}
	if errCode >= 22 && errCode <= 3840 {
		return "available for assignment"
	} else if errCode >= 3841 && errCode <= 4095 {
		return "Private Use"
	} else if errCode >= 4096 && errCode <= 65535 {
		return "available for assignment"
	}
	return ""
}

var mqttV3ExceptionDescs = []string{
	0: "Success",
	1: "unacceptable protocol version",
	2: "identifier rejected",
	3: "Server unavailable",
	4: "bad user name or password",
	5: "not authorized",
}

var mqttV5ExceptionDescs = []string{
	0:   "Success",
	4:   "Dissconnect with Will Message",
	16:  "No matching subscribers",
	17:  "No subscription existed",
	24:  "Continue authentication",
	25:  "Re-authenticate",
	128: "Unspecified error",
	129: "Malformed Packet",
	130: "Protocol Error",
	131: "Implementation specific error",
	132: "Unsupported Protocol Version",
	133: "Client Identifier not valid",
	134: "Bad User Name or Password",
	135: "Not authorized",
	136: "Server unavailable",
	137: "Server busy",
	138: "Banned",
	139: "Server shutting down",
	140: "Bad authentication method",
	141: "Keep Alive timeout",
	142: "Session taken over",
	143: "Topic Filter invalid",
	144: "Topic Name invalid",
	145: "Packet Identifier in use",
	146: "Packet Identifier not found",
	147: "Receive Maximum exceeded",
	148: "Topic Alias invalid",
	149: "Packet too large",
	150: "Message rate too high",
	151: "Quota exceeded",
	152: "Administrative action",
	153: "Payload format invalid",
	154: "Retain not supported",
	155: "QoS not supported",
	156: "Use another server",
	157: "Server moved",
	158: "Shared Subscriptions not supported",
	159: "Connection rate exceeded",
	160: "Maximum connect time",
	161: "Subscription Identifiers not supported",
	162: "Wildcard Subscriptions not supported",
}

func GetMQTTV3ExceptionDesc(errCode uint16) string {
	if errCode > 0 && int(errCode) < len(mqttV3ExceptionDescs) {
		return mqttV3ExceptionDescs[errCode]
	}
	return ""
}

func GetMQTTV5ExceptionDesc(errCode uint16) string {
	if errCode > 0 && int(errCode) < len(mqttV5ExceptionDescs) {
		return mqttV5ExceptionDescs[errCode]
	}
	return ""
}
