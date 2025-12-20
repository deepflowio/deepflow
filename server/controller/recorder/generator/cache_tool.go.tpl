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

package tool

import (
{{- if .HasMapset}}
	mapset "github.com/deckarep/golang-set/v2"
{{- end}}

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// {{.PublicName}} defines cache data structure.
type {{.PublicName}} struct {
{{- range .Fields}}
{{- if .Comment}}
	{{.Name}} {{.Type}} // {{.Comment}}
{{- else}}
	{{.Name}} {{.Type}}
{{- end}}
{{- end}}
}

func (t *{{.PublicName}}) IsValid() bool {
{{- range .Fields}}
{{- if .IsValidationField}}
	return t.{{.Name}} != ""
{{- end}}
{{- end}}
}
{{range .Fields}}

func (t *{{$.PublicName}}) {{.PublicCamelName}}() {{.Type}} {
	return t.{{.Name}}
}
{{- end}}
{{- range .Fields}}
{{- if .HasSetter}}

func (t *{{$.PublicName}}) Set{{.PublicName}}({{.Name}} {{.Type}}) {
	t.{{.Name}} = {{.Name}}
}
{{- end}}
{{- end}}
{{- range .Fields}}
{{- if .IsPlural}}

func (t *{{$.PublicName}}) {{.PublicName}}ToSlice() []int {
	return t.{{.Name}}.ToSlice()
}

func (t *{{$.PublicName}}) AddPodGroupID(id int) {
	t.{{.Name}}.Add(id)
}

func (t *{{$.PublicName}}) RemovePodGroupID(id int) {
	t.{{.Name}}.Remove(id)
}
{{- end}}
{{- end}}

func (t *{{.PublicName}}) reset(dbItem *metadbmodel.{{.PublicName}}, tool *Tool) {
{{- range .Fields}}
{{- if and (not .HasSetter) (not .IsPlural) (not .IsCustom)}}
{{- if .Ref}}
	t.{{.Name}} = tool.{{.Ref}}().GetByLcuuid(dbItem.{{if .DbFieldName}}{{.DbFieldName}}{{else}}{{.PublicName}}{{end}}).ID()
{{- else}}
	t.{{.Name}} = dbItem.{{if .DbFieldName}}{{.DbFieldName}}{{else}}{{.PublicName}}{{end}}
{{- end}}
{{- end}}
{{- end}}
{{- if .HasCustom}}
	t.resetCustom(dbItem, tool)
{{- else}}
{{- range .Fields}}
{{- if .IsCustom}}
	t.{{.Name}} = dbItem.{{if .DbFieldName}}{{.DbFieldName}}{{else}}{{.PublicName}}{{end}}
{{- end}}
{{- end}}
{{- end}}
{{- range .Fields}}
{{- if .IsPlural}}
	t.{{.Name}} = mapset.NewSet[int]()
{{- end}}
{{- end}}
}

func New{{.PublicName}}Collection(t *Tool) *{{.PublicName}}Collection {
	c := new({{.PublicName}}Collection)
{{- if .KeyFields}}
{{- range .KeyFields}}
	c.{{.CamelName}}ToItem = make(map[{{.Type}}]*{{$.PublicName}})
{{- end}}
{{- end}}
{{- if .CollectionExtension}}
	c.resetExt()
{{- end}}
	c.collection = newCollectionBuilder[*{{.PublicName}}]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_{{ToUpper .Name}}_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.{{.PublicName}} { return new(metadbmodel.{{.PublicName}}) }).
		withCacheItemFactory(func() *{{.PublicName}} { return new({{.PublicName}}) }).
{{- if or .KeyFields .CollectionExtension}}
		withExtender(c).
{{- end}}
		build()
	return c
}

// {{.PublicName}}Collection defines a collection that maps individual fields to the {{.PublicName}} cache data structure.
type {{.PublicName}}Collection struct {
	collection[*{{.PublicName}}, *metadbmodel.{{.PublicName}}]
{{- if .KeyFields}}
{{- range .KeyFields}}
	{{.CamelName}}ToItem map[{{.Type}}]*{{$.PublicName}}
{{- end}}
{{- end}}
{{- if .CollectionExtension}}
	{{.PublicName}}CollectionExt
{{- end}}
}

{{- if .KeyFields}}

// OnAfterAdd implements CollectionExtender interface
func (c *{{.PublicName}}Collection) OnAfterAdd(item *{{.PublicName}}, dbItem *metadbmodel.{{.PublicName}}) {
{{- range .KeyFields}}
	if item.{{.PublicCamelName}}() != "" {
		c.{{.CamelName}}ToItem[item.{{.PublicCamelName}}()] = item
	}
{{- end}}
}

// OnAfterUpdate implements CollectionExtender interface  
func (c *{{.PublicName}}Collection) OnAfterUpdate(item *{{.PublicName}}, dbItem *metadbmodel.{{.PublicName}}) {
{{- range .KeyFields}}
	// Remove old {{.Name}} mapping if exists
	for {{.CamelName}}, {{$.PublicName | toLowerCamel}}Item := range c.{{.CamelName}}ToItem {
		if {{$.PublicName | toLowerCamel}}Item == item && {{.CamelName}} != item.{{.PublicCamelName}}() {
			delete(c.{{.CamelName}}ToItem, {{.CamelName}})
			break
		}
	}
	// Add new {{.Name}} mapping
	if item.{{.PublicCamelName}}() != "" {
		c.{{.CamelName}}ToItem[item.{{.PublicCamelName}}()] = item
	}
{{- end}}
}

// OnAfterDelete implements CollectionExtender interface
func (c *{{.PublicName}}Collection) OnAfterDelete(item *{{.PublicName}}, dbItem *metadbmodel.{{.PublicName}}) {
{{- range .KeyFields}}
	if item.{{.PublicCamelName}}() != "" {
		delete(c.{{.CamelName}}ToItem, item.{{.PublicCamelName}}())
	}
{{- end}}
}

{{- range .KeyFields}}
// GetOrLoadBy{{.PublicName}} returns the {{$.PublicName}} by its {{.Name}}, loading from DB if not found in cache.
func (c *{{$.PublicName}}Collection) GetOrLoadBy{{.PublicName}}({{.Name}} {{.Type}}) *{{$.PublicName}} {
	if {{.Name}} == "" {
		return new({{$.PublicName}})
	}

	item, ok := c.{{.CamelName}}ToItem[{{.Name}}]
	if ok {
		return item
	}
	log.Warning("cache %s ({{.Name}}: %s) not found", c.resourceType, {{.Name}})

	var dbItem *metadbmodel.{{$.PublicName}}
	if result := c.tool.metadata.GetDB().Where("{{.Name}} = ?", {{.Name}}).First(&dbItem); result.RowsAffected == 1 {
		c.Add(dbItem)
		return c.{{.CamelName}}ToItem[{{.Name}}]
	} else {
		log.Error("db %s ({{.Name}}: %s) not found", c.resourceType, {{.Name}})
		return new({{$.PublicName}})
	}
}
{{- end}}
{{- end}}
