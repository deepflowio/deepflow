/*
 * Copyright (c) 2022 Yunshan Networks
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

package model

type PodResponse struct {
	ID                int      `json:"ID"`
	Name              string   `json:"NAME"`
	Lcuuid            string   `json:"LCUUID"`
	Alias             string   `json:"ALIAS"`
	State             int      `json:"STATE"`
	Label             string   `json:"LABEL"`
	PodReplicaSetID   int      `json:"POD_RS_ID"`
	PodReplicaSetName string   `json:"POD_RS_NAME"`
	PodGroupID        int      `json:"POD_GROUP_ID"`
	PodGroupType      int      `json:"POD_GROUP_TYPE"`
	PodGroupName      string   `json:"POD_GROUP_NAME"`
	PodNamespaceID    int      `json:"POD_NAMESPACE_ID"`
	PodNamespaceName  string   `json:"POD_NAMESPACE_NAME"`
	PodNodeID         int      `json:"POD_NODE_ID"`
	PodNodeIP         string   `json:"POD_NODE_IP"`
	PodNodeName       string   `json:"POD_NODE_NAME"`
	PodClusterID      int      `json:"POD_CLUSTER_ID"`
	PodClusterName    string   `json:"POD_CLUSTER_NAME"`
	HostID            int      `json:"HOST_ID"`
	VPCID             int      `json:"EPC_ID"`
	VPCName           string   `json:"EPC_NAME"`
	AZLcuuid          string   `json:"AZ"`
	AZName            string   `json:"AZ_NAME"`
	RegionLcuuid      string   `json:"REGION"`
	RegionName        string   `json:"REGION_NAME"`
	SubDomainLcuuid   string   `json:"SUB_DOMAIN"`
	SubDomainName     string   `json:"SUB_DOMAIN_NAME"`
	DomainLcuuid      string   `json:"DOMAIN"`
	DomainName        string   `json:"DOMAIN_NAME"`
	MACs              []string `json:"MACS"`
	IPs               []string `json:"IPS"`
	CreatedAt         string   `json:"CREATED_AT"`
	UpdatedAt         string   `json:"UPDATED_AT"`
	DeletedAt         string   `json:"DELETED_AT"`

	PodServices []struct {
		ID   int    `json:"ID"`
		Name string `json:"NAME"`
	} `json:"POD_SERVICES"`

	Subnets []struct {
		ID   int    `json:"ID"`
		Name string `json:"NAME"`
	} `json:"SUBNETS"`

	VInterfaces []struct {
		MAC int      `json:"MAC"`
		IPs []string `json:"IPS"`
	} `json:"INTERFACES"`
}

type Process struct {
	ResourceType int    `json:"RESOURCE_TYPE"` // 1: vm 14: pod node
	ResourceName string `json:"RESOURCE_NAME"`
	Name         string `json:"NAME"`
	VTapName     string `json:"VTAP_NAME"`
	GProcessID   int    `json:"GPID"`
	GProcessName string `json:"GP_NAME"` // equal to process.process_name
	PID          int    `json:"PID"`
	ProcessName  string `json:"PROCESS_NAME"`
	CommandLine  string `json:"CMD_LINE"`
	UserName     string `json:"USER_NAME"`
	OSAPPTags    string `json:"OS_APP_TAGS"`
	ResourceID   int    `json:"RESOURCE_ID"`
	StartTime    string `json:"START_TIME"`
	UpdatedAt    string `json:"UPDATE_AT"` // TODO 统一为UPDATED_AT
}
