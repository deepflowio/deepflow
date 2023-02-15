package ctl

import (
	"errors"
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/jsonparser"
	"github.com/deepflowio/deepflow/cli/ctl/example"
)

type SubDomainType uint8

const (
	SubDomainTypeCreate SubDomainType = iota
	SubDomainTypeUpdate
)

func RegisterSubDomainCommand() *cobra.Command {
	subDomain := &cobra.Command{
		Use:   "subdomain",
		Short: "subdomain operation commands",
	}

	var listOutput string
	listCmd := &cobra.Command{
		Use:     "list [name]",
		Short:   "list subdomain info",
		Example: "deepflow-ctl subdomain list",
		Run: func(cmd *cobra.Command, args []string) {
			if err := listSubDomain(cmd, args, listOutput); err != nil {
				fmt.Println(err)
			}
		},
	}
	listCmd.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	exampleCmd := &cobra.Command{
		Use:     "example",
		Short:   "example subdomain create yaml",
		Example: "deepflow-ctl subdomain example",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(string(example.YamlSubDomain))
		},
	}

	var createFilename string
	createCmd := &cobra.Command{
		Use:     "create",
		Short:   "create subdomain",
		Example: "deepflow-ctl subdomain create -f filename",
		Run: func(cmd *cobra.Command, args []string) {
			if err := createSubDomain(cmd, createFilename); err != nil {
				fmt.Println(err)
			}
		},
	}
	createCmd.Flags().StringVarP(&createFilename, "filename", "f", "", "create subdomain from file or stdin")
	if err := createCmd.MarkFlagRequired("filename"); err != nil {
		fmt.Println(err)
	}

	var updateFilename string
	updateCmd := &cobra.Command{
		Use:     "update",
		Short:   "update subdomain",
		Example: "deepflow-ctl subdomain update -f ${file_name} ${cluster_id}",
		Run: func(cmd *cobra.Command, args []string) {
			if err := updateSubDomain(cmd, args, updateFilename); err != nil {
				fmt.Println(err)
			}
		},
	}
	updateCmd.Flags().StringVarP(&updateFilename, "filename", "f", "", "update subdomain from file or stdin")
	if err := updateCmd.MarkFlagRequired("filename"); err != nil {
		fmt.Println(err)
	}

	deleteCmd := &cobra.Command{
		Use:     "delete [lcuuid]",
		Short:   "delete subdomain",
		Example: "deepflow-ctl subdomain delete ${cluster_id}",
		Run: func(cmd *cobra.Command, args []string) {
			if err := deleteSubDomain(cmd, args); err != nil {
				fmt.Println(err)
			}
		},
	}

	subDomain.AddCommand(listCmd)
	subDomain.AddCommand(exampleCmd)
	subDomain.AddCommand(createCmd)
	subDomain.AddCommand(updateCmd)
	subDomain.AddCommand(deleteCmd)
	return subDomain
}

func listSubDomain(cmd *cobra.Command, args []string, output string) error {
	var domain string
	if len(args) > 0 {
		domain = args[0]
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v2/sub-domains/", server.IP, server.Port)
	var filter common.Filter
	if domain != "" {
		filter["domain"] = domain
	}
	response, err := common.GetByFilter(url, nil, filter)
	if err != nil {
		return err
	}

	if output == "yaml" {
		jData, _ := response.Get("DATA").MarshalJSON()
		yData, _ := yaml.JSONToYAML(jData)
		fmt.Printf(string(yData))
		return nil
	}
	var (
		nameMaxSize       = jsonparser.GetTheMaxSizeOfAttr(response.Get("DATA"), "NAME")
		lcuuidMaxSize     = jsonparser.GetTheMaxSizeOfAttr(response.Get("DATA"), "LCUUID")
		domainMaxSize     = jsonparser.GetTheMaxSizeOfAttr(response.Get("DATA"), "DOMAIN")
		domainNameMaxSize = jsonparser.GetTheMaxSizeOfAttr(response.Get("DATA"), "DOMAIN_NAME")
		clusterIDMaxSize  = jsonparser.GetTheMaxSizeOfAttr(response.Get("DATA"), "CLUSTER_ID")
	)
	cmdFormat := "%-*s %-*s %-*s %-*s %-*s\n"
	fmt.Printf(cmdFormat, nameMaxSize, "NAME", clusterIDMaxSize, "CLUSTER_ID", lcuuidMaxSize, "LCUUID",
		domainNameMaxSize, "DOMAIN_NAME", domainMaxSize, "DOMAIN")
	for i := range response.Get("DATA").MustArray() {
		sb := response.Get("DATA").GetIndex(i)
		fmt.Printf(cmdFormat,
			nameMaxSize, sb.Get("NAME").MustString(),
			clusterIDMaxSize, sb.Get("CLUSTER_ID").MustString(),
			lcuuidMaxSize, sb.Get("LCUUID").MustString(),
			domainNameMaxSize, sb.Get("DOMAIN_NAME").MustString(),
			domainMaxSize, sb.Get("DOMAIN").MustString())
	}
	return nil
}

func createSubDomain(cmd *cobra.Command, fileName string) error {
	body, err := formatBody(fileName)
	if err != nil {
		return err
	}
	if err = validateSubDomainConfig(body, SubDomainTypeCreate); err != nil {
		return err
	}

	server := common.GetServerInfo(cmd)
	domainLcuuid, err := getLcuuidByDomainName(server, body["DOMAIN_NAME"].(string), body)
	if err != nil {
		return err
	}
	body["DOMAIN"] = domainLcuuid

	url := fmt.Sprintf("http://%s:%d/v2/sub-domains/", server.IP, server.Port)
	_, err = common.CURLPerform("POST", url, body, "")
	if err != nil {
		return err
	}
	return nil
}

func updateSubDomain(cmd *cobra.Command, args []string, fileName string) error {
	body, err := formatBody(fileName)
	if err != nil {
		return err
	}
	if err = validateSubDomainConfig(body, SubDomainTypeUpdate); err != nil {
		return err
	}

	if len(args) == 0 {
		return errors.New("cluster_id is required")
	}
	clusterID := args[0]
	server := common.GetServerInfo(cmd)
	lcuuid, err := getLcuuidByClusterID(server, clusterID)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s:%d/v2/sub-domains/%s/", server.IP, server.Port, lcuuid)
	_, err = common.CURLPerform("PATCH", url, body, "")
	if err != nil {
		return err
	}
	return nil
}

func validateSubDomainConfig(body map[string]interface{}, subdomainType SubDomainType) error {
	if subdomainType == SubDomainTypeCreate {
		_, ok := body["NAME"]
		if !ok {
			return errors.New("name field is required")
		}
		_, ok = body["DOMAIN_NAME"]
		if !ok {
			return errors.New("domain_name field is required")
		}
	}

	config, ok := body["CONFIG"]
	if !ok {
		return errors.New("config field is required")
	}
	v, ok := config.(map[string]interface{})["vpc_uuid"]
	if !ok {
		return errors.New("config.vpc_uuid field is required")
	}
	if _, ok = v.(string); !ok {
		return errors.New("invalid type (config.vpc_uuid), please specify as string")
	}
	return nil
}

func deleteSubDomain(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("cluster_id is required")
	}
	clusterID := args[0]

	server := common.GetServerInfo(cmd)
	lcuuid, err := getLcuuidByClusterID(server, clusterID)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s:%d/v2/sub-domains/%s/", server.IP, server.Port, lcuuid)
	_, err = common.CURLPerform("DELETE", url, nil, "")
	if err != nil {
		return err
	}
	return nil
}

func getLcuuidByDomainName(server *common.Server, domainName string,
	body map[string]interface{}) (string, error) {
	url := fmt.Sprintf("http://%s:%d/v2/domains", server.IP, server.Port)
	response, err := common.GetByFilter(url, body, common.Filter{"name": domainName})
	if err != nil {
		return "", err
	}
	if len(response.Get("DATA").MustArray()) == 0 {
		return "", fmt.Errorf("invalid domain name: %v", domainName)
	}

	domainLcuuid := response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
	if len(domainLcuuid) == 0 {
		return "", errors.New("domain lcuuid corresponding to the domain name is null")
	}
	domainType := response.Get("DATA").GetIndex(0).Get("TYPE").MustInt()
	if common.DomainType(domainType) == common.DOMAIN_TYPE_KUBERNETES {
		return "", fmt.Errorf("domain_type=%v is not supported", domainType)
	}
	return domainLcuuid, nil
}

func getLcuuidByClusterID(server *common.Server, clusterID string) (string, error) {
	url := fmt.Sprintf("http://%s:%d/v2/sub-domains", server.IP, server.Port)
	response, err := common.GetByFilter(url, nil, common.Filter{"cluster_id": clusterID})
	if err != nil {
		return "", err
	}
	if len(response.Get("DATA").MustArray()) == 0 {
		return "", fmt.Errorf("invalid cluster_id: %v", clusterID)
	}
	return response.Get("DATA").GetIndex(0).Get("LCUUID").MustString(), nil
}
