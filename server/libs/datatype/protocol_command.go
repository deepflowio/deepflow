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

package datatype

import "strconv"

var DnsCommandString = []string{
	0:   "",
	1:   "A",
	2:   "NS",
	3:   "MD",
	4:   "MF",
	5:   "CNAME",
	6:   "SOA",
	7:   "MB",
	8:   "MG",
	9:   "MR",
	10:  "NULL",
	11:  "WKS",
	12:  "PTR",
	13:  "HINFO",
	14:  "MINFO",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	252: "AXFR",
	253: "MAILB",
	254: "MAILA",
	255: "ANY",
}

func GetDNSQueryType(query uint8) string {
	if (query >= 0 && query <= 16) ||
		query == 28 ||
		(query >= 252 && query <= 255) {
		return DnsCommandString[query]
	}
	return strconv.Itoa(int(query))
}

type MysqlCommand uint8

const (
	_COM_SLEEP               MysqlCommand = 0x00
	_COM_QUIT                MysqlCommand = 0x01
	_COM_INIT_DB             MysqlCommand = 0x02
	_COM_QUERY               MysqlCommand = 0x03
	_COM_FIELD_LIST          MysqlCommand = 0x04
	_COM_CREATE_DB           MysqlCommand = 0x05
	_COM_DROP_DB             MysqlCommand = 0x06
	_COM_REFRESH             MysqlCommand = 0x07
	_COM_SHUTDOWN            MysqlCommand = 0x08
	_COM_STATISTICS          MysqlCommand = 0x09
	_COM_PROCESS_INFO        MysqlCommand = 0x0a
	_COM_CONNECT             MysqlCommand = 0x0b
	_COM_PROCESS_KILL        MysqlCommand = 0x0c
	_COM_DEBUG               MysqlCommand = 0x0d
	_COM_PING                MysqlCommand = 0x0e
	_COM_TIME                MysqlCommand = 0x0f
	_COM_DELAYED_INSERT      MysqlCommand = 0x10
	_COM_CHANGE_USER         MysqlCommand = 0x11
	_COM_BINLOG_DUMP         MysqlCommand = 0x12
	_COM_TABLE_DUMP          MysqlCommand = 0x13
	_COM_CONNECT_OUT         MysqlCommand = 0x14
	_COM_REGISTER_SLAVE      MysqlCommand = 0x15
	_COM_STMT_PREPARE        MysqlCommand = 0x16
	_COM_STMT_EXECUTE        MysqlCommand = 0x17
	_COM_STMT_SEND_LONG_DATA MysqlCommand = 0x18
	_COM_STMT_CLOSE          MysqlCommand = 0x19
	_COM_STMT_RESET          MysqlCommand = 0x1a
	_COM_SET_OPTION          MysqlCommand = 0x1b
	_COM_STMT_FETCH          MysqlCommand = 0x1c
	_COM_DAEMON              MysqlCommand = 0x1d
	_COM_BINLOG_DUMP_GTID    MysqlCommand = 0x1e
	_COM_RESET_CONNECTION    MysqlCommand = 0x1f
)

var MysqlCommandString = []string{
	_COM_SLEEP:               "COM_SLEEP",
	_COM_QUIT:                "COM_QUIT",
	_COM_INIT_DB:             "COM_INIT_DB",
	_COM_QUERY:               "COM_QUERY",
	_COM_FIELD_LIST:          "COM_FIELD_LIST",
	_COM_CREATE_DB:           "COM_CREATE_DB",
	_COM_DROP_DB:             "COM_DROP_DB",
	_COM_REFRESH:             "COM_REFRESH",
	_COM_SHUTDOWN:            "COM_SHUTDOWN",
	_COM_STATISTICS:          "COM_STATISTICS",
	_COM_PROCESS_INFO:        "COM_PROCESS_INFO",
	_COM_CONNECT:             "COM_CONNECT",
	_COM_PROCESS_KILL:        "COM_PROCESS_KILL",
	_COM_DEBUG:               "COM_DEBUG",
	_COM_PING:                "COM_PING",
	_COM_TIME:                "COM_TIME",
	_COM_DELAYED_INSERT:      "COM_DELAYED_INSERT",
	_COM_CHANGE_USER:         "COM_CHANGE_USER",
	_COM_BINLOG_DUMP:         "COM_BINLOG_DUMP",
	_COM_TABLE_DUMP:          "COM_TABLE_DUMP",
	_COM_CONNECT_OUT:         "COM_CONNECT_OUT",
	_COM_REGISTER_SLAVE:      "COM_REGISTER_SLAVE",
	_COM_STMT_PREPARE:        "COM_STMT_PREPARE",
	_COM_STMT_EXECUTE:        "COM_STMT_EXECUTE",
	_COM_STMT_SEND_LONG_DATA: "COM_STMT_SEND_LONG_DATA",
	_COM_STMT_CLOSE:          "COM_STMT_CLOSE",
	_COM_STMT_RESET:          "COM_STMT_RESET",
	_COM_SET_OPTION:          "COM_SET_OPTION",
	_COM_STMT_FETCH:          "COM_STMT_FETCH",
	_COM_DAEMON:              "COM_DAEMON",
	_COM_BINLOG_DUMP_GTID:    "COM_BINLOG_DUMP_GTID",
	_COM_RESET_CONNECTION:    "COM_RESET_CONNECTION",
}

func (m MysqlCommand) String() string {
	if m <= _COM_RESET_CONNECTION {
		return MysqlCommandString[m]
	}
	return strconv.Itoa(int(m))
}

type KafkaCommand uint8

const (
	Produce                      KafkaCommand = 0
	Fetch                        KafkaCommand = 1
	ListOffsets                  KafkaCommand = 2
	Metadata                     KafkaCommand = 3
	LeaderAndIsr                 KafkaCommand = 4
	StopReplica                  KafkaCommand = 5
	UpdateMetadata               KafkaCommand = 6
	ControlledShutdown           KafkaCommand = 7
	OffsetCommit                 KafkaCommand = 8
	OffsetFetch                  KafkaCommand = 9
	FindCoordinator              KafkaCommand = 10
	JoinGroup                    KafkaCommand = 11
	Heartbeat                    KafkaCommand = 12
	LeaveGroup                   KafkaCommand = 13
	SyncGroup                    KafkaCommand = 14
	DescribeGroups               KafkaCommand = 15
	ListGroups                   KafkaCommand = 16
	SaslHandshake                KafkaCommand = 17
	ApiVersions                  KafkaCommand = 18
	CreateTopics                 KafkaCommand = 19
	DeleteTopics                 KafkaCommand = 20
	DeleteRecords                KafkaCommand = 21
	InitProducerId               KafkaCommand = 22
	OffsetForLeaderEpoch         KafkaCommand = 23
	AddPartitionsToTxn           KafkaCommand = 24
	AddOffsetsToTxn              KafkaCommand = 25
	EndTxn                       KafkaCommand = 26
	WriteTxnMarkers              KafkaCommand = 27
	TxnOffsetCommit              KafkaCommand = 28
	DescribeAcls                 KafkaCommand = 29
	CreateAcls                   KafkaCommand = 30
	DeleteAcls                   KafkaCommand = 31
	DescribeConfigs              KafkaCommand = 32
	AlterConfigs                 KafkaCommand = 33
	AlterReplicaLogDirs          KafkaCommand = 34
	DescribeLogDirs              KafkaCommand = 35
	SaslAuthenticate             KafkaCommand = 36
	CreatePartitions             KafkaCommand = 37
	CreateDelegationToken        KafkaCommand = 38
	RenewDelegationToken         KafkaCommand = 39
	ExpireDelegationToken        KafkaCommand = 40
	DescribeDelegationToken      KafkaCommand = 41
	DeleteGroups                 KafkaCommand = 42
	ElectLeaders                 KafkaCommand = 43
	IncrementalAlterConfigs      KafkaCommand = 44
	AlterPartitionReassignments  KafkaCommand = 45
	ListPartitionReassignments   KafkaCommand = 46
	OffsetDelete                 KafkaCommand = 47
	DescribeClientQuotas         KafkaCommand = 48
	AlterClientQuotas            KafkaCommand = 49
	DescribeUserScramCredentials KafkaCommand = 50
	AlterUserScramCredentials    KafkaCommand = 51
	AlterIsr                     KafkaCommand = 56
	UpdateFeatures               KafkaCommand = 57
	DescribeCluster              KafkaCommand = 60
	DescribeProducers            KafkaCommand = 61
	DescribeTransactions         KafkaCommand = 65
	ListTransactions             KafkaCommand = 66
	AllocateProducerIds          KafkaCommand = 67
)

var KafkaCommandString = []string{
	Produce:                      "Produce",
	Fetch:                        "Fetch",
	ListOffsets:                  "ListOffsets",
	Metadata:                     "Metadata",
	LeaderAndIsr:                 "LeaderAndIsr",
	StopReplica:                  "StopReplica",
	UpdateMetadata:               "UpdateMetadata",
	ControlledShutdown:           "ControlledShutdown",
	OffsetCommit:                 "OffsetCommit",
	OffsetFetch:                  "OffsetFetch",
	FindCoordinator:              "FindCoordinator",
	JoinGroup:                    "JoinGroup",
	Heartbeat:                    "Heartbeat",
	LeaveGroup:                   "LeaveGroup",
	SyncGroup:                    "SyncGroup",
	DescribeGroups:               "DescribeGroups",
	ListGroups:                   "ListGroups",
	SaslHandshake:                "SaslHandshake",
	ApiVersions:                  "ApiVersions",
	CreateTopics:                 "CreateTopics",
	DeleteTopics:                 "DeleteTopics",
	DeleteRecords:                "DeleteRecords",
	InitProducerId:               "InitProducerId",
	OffsetForLeaderEpoch:         "OffsetForLeaderEpoch",
	AddPartitionsToTxn:           "AddPartitionsToTxn",
	AddOffsetsToTxn:              "AddOffsetsToTxn",
	EndTxn:                       "EndTxn",
	WriteTxnMarkers:              "WriteTxnMarkers",
	TxnOffsetCommit:              "TxnOffsetCommit",
	DescribeAcls:                 "DescribeAcls",
	CreateAcls:                   "CreateAcls",
	DeleteAcls:                   "DeleteAcls",
	DescribeConfigs:              "DescribeConfigs",
	AlterConfigs:                 "AlterConfigs",
	AlterReplicaLogDirs:          "AlterReplicaLogDirs",
	DescribeLogDirs:              "DescribeLogDirs",
	SaslAuthenticate:             "SaslAuthenticate",
	CreatePartitions:             "CreatePartitions",
	CreateDelegationToken:        "CreateDelegationToken",
	RenewDelegationToken:         "RenewDelegationToken",
	ExpireDelegationToken:        "ExpireDelegationToken",
	DescribeDelegationToken:      "DescribeDelegationToken",
	DeleteGroups:                 "DeleteGroups",
	ElectLeaders:                 "ElectLeaders",
	IncrementalAlterConfigs:      "IncrementalAlterConfigs",
	AlterPartitionReassignments:  "AlterPartitionReassignments",
	ListPartitionReassignments:   "ListPartitionReassignments",
	OffsetDelete:                 "OffsetDelete",
	DescribeClientQuotas:         "DescribeClientQuotas",
	AlterClientQuotas:            "AlterClientQuotas",
	DescribeUserScramCredentials: "DescribeUserScramCredentials",
	AlterUserScramCredentials:    "AlterUserScramCredentials",
	AlterIsr:                     "AlterIsr",
	UpdateFeatures:               "UpdateFeatures",
	DescribeCluster:              "DescribeCluster",
	DescribeProducers:            "DescribeProducers",
	DescribeTransactions:         "DescribeTransactions",
	ListTransactions:             "ListTransactions",
	AllocateProducerIds:          "AllocateProducerIds",
}

func (m KafkaCommand) String() string {
	if m <= AllocateProducerIds {
		return KafkaCommandString[m]
	}
	return strconv.Itoa(int(m))
}
