/*
 * Copyright (c) 2023 Yunshan Networks
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

package ctl

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/example"
)

func RegisterDomainAdditionalResourceCommand() *cobra.Command {
	DomainAdditionalResource := &cobra.Command{
		Use:   "additional-resource",
		Short: "additional-resource operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'apply | example'.\n")
		},
	}

	var applyFilename string
	apply := &cobra.Command{
		Use:     "apply",
		Short:   "apply domain additional resource file",
		Example: "deepflow-ctl domain additional-resource apply -f xxx.yaml, use example to see yaml templete",
		Run: func(cmd *cobra.Command, args []string) {
			applyDomainAdditionalResource(cmd, args, applyFilename)
		},
	}
	apply.Flags().StringVarP(&applyFilename, "filename", "f", "", "apply domain additional resource from yaml")
	apply.MarkFlagRequired("filename")

	exampleCmd := &cobra.Command{
		Use:     "example",
		Example: "domain additional-resource example",
		Run: func(cmd *cobra.Command, args []string) {
			exampleDomainAdditionalResourceConfig(cmd)
		},
	}

	var resourceType, resourceName string
	list := &cobra.Command{
		Use:     "list",
		Short:   "list domain additional resource",
		Example: "deepflow-ctl domain additional-resource list",
		Run: func(cmd *cobra.Command, args []string) {
			if resourceName != "" && resourceType == "" {
				fmt.Printf("please enter resource type, resource name(%v)\n", resourceName)
				return
			}
			listDomainAdditionalResource(cmd, resourceType, resourceName)
		},
	}
	list.Flags().StringVarP(&resourceType, "type", "", "", "resource type, support: az, vpc, subnet, host, chost, lb, cloud-tag")
	list.Flags().StringVarP(&resourceName, "name", "", "", "resource name, need to set the type value first")

	DomainAdditionalResource.AddCommand(apply)
	DomainAdditionalResource.AddCommand(list)
	DomainAdditionalResource.AddCommand(exampleCmd)
	return DomainAdditionalResource
}

func applyDomainAdditionalResource(cmd *cobra.Command, args []string, filename string) {
	body, err := loadBodyFromFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/domain-additional-resources/", server.IP, server.Port)
	_, err = common.CURLPerform("PUT", url, body, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

var additionalListTemplate = `{{- if .AZS }}
azs:{{ range .AZS }}
- name: {{ .NAME }}
  uuid: {{ .UUID }}
  domain_uuid: {{ .DOMAIN_UUID }}
{{- end }}{{ end }}

{{- if .VPCS }}
vpcs:{{ range .VPCS }}
- name: {{ .NAME }}
  uuid: {{ .UUID }}
  domain_uuid: {{ .DOMAIN_UUID }}
{{- end }}{{ end }}

{{- if .SUBNETS }}
subnets:{{ range .SUBNETS }}
- name: {{ .NAME }}
  uuid: {{ .UUID }}
  type: {{ .TYPE }}
  is_vip: {{ .IS_VIP }}
  vpc_uuid: {{ .VPC_UUID }}
  {{- if .AZ_UUID }}az_uuid: {{ .AZ_UUID }}{{ end }}
  domain_uuid: {{ .DOMAIN_UUID }}
  cidrs:{{ range .CIDRS }} 
  - {{ . }}
  {{- end }}
{{- end }}{{ end }}

{{- if .HOSTS }}
hosts:{{ range .HOSTS }}
- name: {{ .NAME }}
  uuid: {{ .UUID }}
  ip: {{ .IP }}
  type: {{ .TYPE }}
  az_uuid: {{ .AZ_UUID }}
  domain_uuid: {{ .DOMAIN_UUID }}
  {{-  if .VINTERFACES }}
  vinterfaces: {{ range .VINTERFACES }}
  - mac: {{ .MAC }}
    name: {{ .NAME }}
    subnet_uuid: {{ .SUBNET_UUID }}
    {{- if .IPS }}
    ips:{{ range .IPS }}
    - {{ . }}
    {{- end }}
    {{- end }}
  {{- end }}
  {{- end }}
{{- end }}{{- end }}

{{- if .CHOSTS }}
chosts:{{ range .CHOSTS }}
- name: {{ .NAME }}
  uuid: {{ .UUID }}
  host_ip: {{ .HOST_IP }}
  type: {{ .TYPE }}
  vpc_uuid: {{ .VPC_UUID }}
  az_uuid: {{ .AZ_UUID }}
  domain_uuid: {{ .DOMAIN_UUID }}
  {{-  if .VINTERFACES }}
  vinterfaces: {{ range .VINTERFACES }}
  - mac: {{ .MAC }}
    subnet_uuid: {{ .SUBNET_UUID }}
    {{- if .IPS }}
    ips:{{ range .IPS }}
    - {{ . }}
    {{- end }}
    {{- end }}
  {{- end }}
  {{- end }}
{{- end }}{{- end }}

{{- if .LBS }}
lbs:{{ range .LBS }}
- name: {{ .NAME }}
  model: {{ .MODEL }}
  vpc_uuid: {{ .VPC_UUID }}
  domain_uuid: {{ .DOMAIN_UUID }}
  region_uuid: {{ .REGION_UUID }}
  {{-  if .VINTERFACES }}
  vinterfaces: {{ range .VINTERFACES }}
  - mac: {{ .MAC }}
    subnet_uuid: {{ .SUBNET_UUID }}
    {{- if .IPS }}
    ips:{{ range .IPS}} 
    - {{ . }}
    {{- end }}
    {{- end }}
  {{- end }}
  {{- end }}
  {{- if .LB_LISTENERS }}
  lb_listeners:{{ range .LB_LISTENERS }}
  - {{ if .NAME }}name: {{ .NAME }}{{ end }} 
    protocol: {{ .PROTOCOL }}
    ip: {{ .IP }}
    port: {{ .PORT }}
    {{ if .LB_TARGET_SERVERS }}lb_target_servers:{{range  .LB_TARGET_SERVERS }}
    - ip: {{ .IP }}
      port: {{ .PORT }}
      {{ end }}
	{{- end }}
  {{- end }}
  {{- end }}
{{- end }}{{ end }}

{{- if .CLOUD_TAGS }}
cloud_tags:{{ range .CLOUD_TAGS }}
- resource_type: {{ .RESOURCE_TYPE }}
  resource_name: {{ .RESOURCE_NAME }}
  domain_uuid: {{ .DOMAIN_UUID }}
  {{- if .SUBDOMAIN_UUID }}
  subdomain_uuid: {{ .SUBDOMAIN_UUID }}{{ end }}
  tags: {{ range .TAGS }}
  - key: {{ .KEY }}
    value: {{ .VALUE }}
  {{- end }}
{{- end }}{{ end }}
`

func listDomainAdditionalResource(cmd *cobra.Command, resourceType, resourceName string) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/domain-additional-resources/?type=%s&name=%s", server.IP, server.Port, resourceType, resourceName)
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	data, err := response.Get("DATA").Map()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	t := template.Must(template.New("domain_additional_list").Parse(additionalListTemplate))
	t.Execute(os.Stdout, data)
}

func exampleDomainAdditionalResourceConfig(cmd *cobra.Command) {
	fmt.Printf(string(example.YamlDomainAdditionalResourceReader))
}

func loadBodyFromFile(filename string) (map[string]interface{}, error) {
	var body map[string]interface{}
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, &body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
