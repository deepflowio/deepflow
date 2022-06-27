package tagrecorder

import (
	"errors"

	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

type IconData struct {
	ID   int
	Name string
}

type IconKey struct {
	NodeType string
	SubType  int
}

func (c *TagRecorder) UpdateIconInfo() (map[string]int, map[IconKey]int, error) {
	domainToIconID := make(map[string]int)
	resourceToIconID := make(map[IconKey]int)
	body := make(map[string]interface{})
	response, err := common.CURLPerform("GET", "http://df-web:20825/v1/icons", body)
	if err != nil {
		return domainToIconID, resourceToIconID, err
	}
	if len(response.Get("DATA").MustArray()) == 0 {
		return domainToIconID, resourceToIconID, errors.New("no data in get icons response")
	}
	Icons := []IconData{}
	for i, _ := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		for k, _ := range IconNameToDomainType {
			if data.Get("NAME").MustString() == k {
				var iconData IconData
				iconData.Name = data.Get("NAME").MustString()
				iconData.ID = data.Get("ID").MustInt()
				Icons = append(Icons, iconData)
			}
		}
		if data.Get("NODE_TYPE").MustString() == "" || data.Get("ID").MustInt() == 0 {
			continue
		}
		resourceType, ok := DBNodeTypeToResourceType[data.Get("NODE_TYPE").MustString()]
		if !ok {
			continue
		}
		key := IconKey{
			NodeType: resourceType,
			SubType:  data.Get("SUB_TYPE").MustInt(),
		}
		resourceToIconID[key] = data.Get("ID").MustInt()

	}
	domainTypeToDefaultIconID := make(map[int]int)
	for _, icon := range Icons {
		for _, domainType := range IconNameToDomainType[icon.Name] {
			domainTypeToDefaultIconID[domainType] = icon.ID
		}
	}
	var domains []mysql.Domain
	mysql.Db.Find(&domains)
	for _, domain := range domains {
		if domain.IconID != 0 {
			domainToIconID[domain.Lcuuid] = domain.IconID
		} else {
			defaultIconID, ok := domainTypeToDefaultIconID[domain.Type]
			if ok {
				domainToIconID[domain.Lcuuid] = defaultIconID
			} else {
				domainToIconID[domain.Lcuuid] = common.DEFAULT_DOMAIN_ICON
			}
		}
	}
	return domainToIconID, resourceToIconID, nil
}
