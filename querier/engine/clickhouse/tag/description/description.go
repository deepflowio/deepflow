package description

type TagDescription struct {
	Name        string
	ClientName  string
	ServerName  string
	DisplayName string
	Type        string
}

func NewTagDescription(name, clientName, serverName, displayName, tagType string) *TagDescription {
	return &TagDescription{
		Name:        name,
		ClientName:  clientName,
		ServerName:  serverName,
		DisplayName: displayName,
		Type:        tagType,
	}
}

func GetTagDescriptions(db, table string) map[string][]interface{} {
	values := []interface{}{}
	columns := []interface{}{}
	columns = append(columns, "name", "client_name", "server_name", "display_name", "type")
	switch db {
	case "flow_log":
		switch table {
		case "l4_flow_log":
			for _, tag := range ResourceTags {
				values = append(values, []interface{}{tag.Name, tag.ServerName, tag.ClientName, tag.DisplayName, tag.Type})
			}
		}
	}
	data := make(map[string][]interface{})
	data["values"] = values
	data["columns"] = columns
	return data
}
