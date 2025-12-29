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

package tagrecorder

const (
	SQL_CREATE_DICT               = "CREATE DICTIONARY %s.%s\n"
	SQL_SOURCE_MYSQL              = "SOURCE(%s(%sPORT %d USER '%s' PASSWORD '%s' %sDB %s TABLE %s UPDATE_FIELD 'updated_at' INVALIDATE_QUERY 'select max(updated_at) from %s'))\n"
	SQL_SOURCE_DM                 = "SOURCE(ODBC(CONNECTION_STRING 'DSN=%s' DB %s TABLE %s INVALIDATE_QUERY 'select max(updated_at) from %s.%s'))\n"
	SQL_LIFETIME                  = "LIFETIME(MIN 30 MAX %d)\n"
	SQL_LAYOUT_FLAT               = "LAYOUT(FLAT())"
	SQL_LAYOUT_COMPLEX_KEY_HASHED = "LAYOUT(COMPLEX_KEY_HASHED())"
)

// sqls to create dict using subscriber framework
const (
	CREATE_DEVICE_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `devicetype` UInt64,\n" +
		"    `deviceid` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `uid` String,\n" +
		"    `hostname` String,\n" +
		"    `ip` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY devicetype, deviceid\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_COMPLEX_KEY_HASHED
	CREATE_AZ_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_CHOST_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `host_id` UInt64,\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `hostname` String,\n" +
		"    `ip` String,\n" +
		"    `subnet_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_BIZ_SERVICE_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `service_group_name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_VPC_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `uid` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_VL2_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64,\n" +
		"    `l3_epc_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_POD_CLUSTER_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_POD_NODE_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64,\n" +
		"    `pod_cluster_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_POD_NS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `pod_cluster_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_POD_INGRESS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `sub_domain_id` UInt64,\n" +
		"    `pod_cluster_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_POD_SERVICE_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `pod_cluster_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_POD_GROUP_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `pod_group_type` UInt64,\n" +
		"    `icon_id` Int64,\n" +
		"    `pod_cluster_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_POD_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `pod_cluster_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `pod_node_id` UInt64,\n" +
		"    `pod_service_id` UInt64,\n" +
		"    `pod_group_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_GPROCESS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `name` String,\n" +
		"    `icon_id` Int64,\n" +
		"    `chost_id` Int64,\n" +
		"    `l3_epc_id` Int64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT

	CREATE_K8S_ANNOTATION_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `key` String,\n" +
		"    `value` String,\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id, key\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_COMPLEX_KEY_HASHED
	CREATE_K8S_ANNOTATIONS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `annotations` String,\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_K8S_ENV_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `key` String,\n" +
		"    `value` String,\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id, key\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_COMPLEX_KEY_HASHED
	CREATE_K8S_ENVS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `envs` String,\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_K8S_LABEL_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `key` String,\n" +
		"    `value` String,\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id, key\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_COMPLEX_KEY_HASHED
	CREATE_K8S_LABELS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `labels` String,\n" +
		"    `l3_epc_id` UInt64,\n" +
		"    `pod_ns_id` UInt64,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_POD_NS_CLOUD_TAG_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `key` String,\n" +
		"    `value` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id, key\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_COMPLEX_KEY_HASHED
	CREATE_POD_NS_CLOUD_TAGS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `cloud_tags` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_CHOST_CLOUD_TAG_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `key` String,\n" +
		"    `value` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id, key\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_COMPLEX_KEY_HASHED
	CREATE_CHOST_CLOUD_TAGS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `cloud_tags` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
	CREATE_OS_APP_TAG_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `key` String,\n" +
		"    `value` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id, key\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_COMPLEX_KEY_HASHED
	CREATE_OS_APP_TAGS_DICTIONARY_SQL = SQL_CREATE_DICT +
		"(\n" +
		"    `id` UInt64,\n" +
		"    `os_app_tags` String,\n" +
		"    `team_id` UInt64,\n" +
		"    `domain_id` UInt64,\n" +
		"    `sub_domain_id` UInt64\n" +
		")\n" +
		"PRIMARY KEY id\n" +
		"%s" +
		SQL_LIFETIME +
		SQL_LAYOUT_FLAT
)
