package ctl

import (
	"errors"
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/deepflowys/deepflow/cli/ctl/common"
	"github.com/deepflowys/deepflow/cli/ctl/common/jsonparser"
	"github.com/deepflowys/deepflow/cli/ctl/example"
)

var ErrDomainDataIsNull = errors.New("ErrDomainDataIsNull")

func RegisterSubDomainCommand() *cobra.Command {
	subDomain := &cobra.Command{
		Use:   "sub-domain",
		Short: "sub-domain operation commands",
	}

	var listOutput string
	listCmd := &cobra.Command{
		Use:     "list [name]",
		Short:   "list sub-domain info",
		Example: "deepflow-ctl sub-domain list",
		Run: func(cmd *cobra.Command, args []string) {
			if err := listSubDomain(cmd, args, listOutput); err != nil {
				fmt.Println(err)
			}
		},
	}
	listCmd.Flags().StringVarP(&listOutput, "output", "o", "", "output format")

	exampleCmd := &cobra.Command{
		Use:     "example",
		Short:   "example sub-domain create yaml",
		Example: "deepflow-ctl domain example",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(string(example.YamlSubDomain))
		},
	}

	var createFilename string
	createCmd := &cobra.Command{
		Use:     "create",
		Short:   "create sub-domain",
		Example: "deepflow-ctl sub-domain create -f filename",
		Run: func(cmd *cobra.Command, args []string) {
			if err := createSubDomain(cmd, createFilename); err != nil {
				fmt.Println(err)
			}
		},
	}
	createCmd.Flags().StringVarP(&createFilename, "filename", "f", "", "create sub-domain from file or stdin")
	if err := createCmd.MarkFlagRequired("filename"); err != nil {
		fmt.Println(err)
	}

	var updateFilename string
	updateCmd := &cobra.Command{
		Use:     "update",
		Short:   "update sub-domain",
		Example: "deepflow-ctl sub-domain update -f k8s.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			if err := updateSubDomain(cmd, updateFilename); err != nil {
				fmt.Println(err)
			}
		},
	}
	updateCmd.Flags().StringVarP(&updateFilename, "filename", "f", "", "update domain from file or stdin")
	if err := updateCmd.MarkFlagRequired("filename"); err != nil {
		fmt.Println(err)
	}

	deleteCmd := &cobra.Command{
		Use:     "delete [lcuuid]",
		Short:   "delete sub-domain",
		Example: "deepflow-ctl sub-domain delete deepflow-sub-domain",
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
	if domain != "" {
		url += fmt.Sprintf("?domain=%s", domain)
	}

	response, err := common.CURLPerform("GET", url, nil, "")
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
		domainMaxSize     = jsonparser.GetTheMaxSizeOfAttr(response.Get("DOMAIN"), "DOMAIN")
		domainNameMaxSize = jsonparser.GetTheMaxSizeOfAttr(response.Get("DOMAIN_NAME"), "DOMAIN_NAME")
	)
	cmdFormat := "%-*s %-*s %-*s %-*s\n"
	fmt.Printf(cmdFormat, nameMaxSize, "NAME", lcuuidMaxSize, "LCUUID",
		domainNameMaxSize, "DOMAIN_NAME", domainMaxSize, "DOMAIN")
	for i := range response.Get("DATA").MustArray() {
		sb := response.Get("DATA").GetIndex(i)
		fmt.Printf(cmdFormat,
			nameMaxSize, sb.Get("NAME").MustString(), lcuuidMaxSize, sb.Get("LCUUID").MustString(),
			domainNameMaxSize, sb.Get("DOMAIN_NAME").MustString(), domainMaxSize, sb.Get("DOMAIN").MustString())
	}
	return nil
}

func createSubDomain(cmd *cobra.Command, fileName string) error {
	server := common.GetServerInfo(cmd)
	body, domainLuccid, err := validateAndFormatBody(server, fileName)
	if err != nil {
		return err
	}
	body["DOMAIN"] = domainLuccid
	url := fmt.Sprintf("http://%s:%d/v2/sub-domains/", server.IP, server.Port)
	_, err = common.CURLPerform("POST", url, body, "")
	if err != nil {
		return err
	}
	return nil
}

func validateAndFormatBody(server *common.Server, fileName string) (map[string]interface{}, string, error) {
	body, err := formatBody(fileName)
	if err != nil {
		return nil, "", err
	}
	if err = validateSubDomainConfig(body); err != nil {
		return nil, "", err
	}

	// 校验是否存在同名的 domain
	domainLuccid, err := getLCUUIDByDomain(server, body["DOMAIN_NAME"].(string), body)
	// 如果 err 有错并不是 ErrDomainDataIsNull 错误，则返回 err
	if err != nil && !errors.Is(err, ErrDomainDataIsNull) {
		return nil, "", err
	}
	if len(domainLuccid) == 0 {
		return nil, "", errors.New("domain lcuuid corresponding to the domain name is null")
	}
	return body, domainLuccid, nil
}

func updateSubDomain(cmd *cobra.Command, fileName string) error {
	server := common.GetServerInfo(cmd)
	body, domainLuccid, err := validateAndFormatBody(server, fileName)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s:%d/v2/sub-domains/?domain=%s", server.IP, server.Port, domainLuccid)
	response, err := common.CURLPerform("GET", url, body, "")
	if err != nil {
		return err
	}

	if len(response.Get("DATA").MustArray()) == 0 {
		return fmt.Errorf("cannot to get sub-domain, domain=%v", domainLuccid)
	}
	lcuuid := response.Get("DATA").GetIndex(0).Get("LCUUID").MustString()
	url = fmt.Sprintf("http://%s:%d/v2/sub-domains/%s/", server.IP, server.Port, lcuuid)
	_, err = common.CURLPerform("PATCH", url, body, "")
	if err != nil {
		return err
	}
	return nil
}

func validateSubDomainConfig(body map[string]interface{}) error {
	_, ok := body["NAME"]
	if !ok {
		return errors.New("name field is required")
	}
	_, ok = body["DOMAIN_NAME"]
	if !ok {
		return errors.New("domain_name field is required")
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
		return fmt.Errorf("must specify lcuuid.\nExample: %s", cmd.Example)
	}

	server := common.GetServerInfo(cmd)
	lcuuid := args[0]
	url := fmt.Sprintf("http://%s:%d/v2/sub-domains/%s/", server.IP, server.Port, lcuuid)
	_, err := common.CURLPerform("DELETE", url, nil, "")
	if err != nil {
		return err
	}
	return nil
}

func getLCUUIDByDomain(server *common.Server, domainName string, body map[string]interface{}) (string, error) {
	url := fmt.Sprintf("http://%s:%d/v2/domains/?name=%s", server.IP, server.Port, domainName)
	response, err := common.CURLPerform("GET", url, body, "")
	if err != nil {
		return "", err
	}
	if len(response.Get("DATA").MustArray()) == 0 {
		return "", fmt.Errorf("cannot get domain luccid by name, name=%v, %w", domainName, ErrDomainDataIsNull)
	}
	return response.Get("DATA").GetIndex(0).Get("LCUUID").MustString(), nil
}
