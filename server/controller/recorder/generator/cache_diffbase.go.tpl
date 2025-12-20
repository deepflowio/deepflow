/**
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

package diffbase

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

type {{.PublicName}} struct {
	ResourceBase
{{- range .Fields}}
{{- if .Comment}}
	{{.Name}} {{.Type}} // {{.Comment}}
{{- else}}
	{{.Name}} {{.Type}}
{{- end}}
{{- end}}
}

func (a *{{.PublicName}}) reset(dbItem *metadbmodel.{{.PublicName}}, tool *tool.Tool) {
{{- range .Fields}}
{{- if .Ref}}
{{- if and .DbFieldName (or (hasSuffix .Name "Lcuuid") (hasSuffix .Name "LCuuid"))}}
{{- if .RefField}}
	a.{{.Name}} = tool.{{.Ref}}().GetBy{{.RefField}}(dbItem.{{.DbFieldName}}).{{.RefField}}()
{{- else}}
	a.{{.Name}} = tool.{{.Ref}}().GetByID(dbItem.{{.DbFieldName}}).Lcuuid()
{{- end}}
{{- else}}
{{- if .RefField}}
	a.{{.Name}} = tool.{{.Ref}}().GetBy{{.RefField}}(dbItem.{{if .DbFieldName}}{{.DbFieldName}}{{else}}{{.PublicCamelName}}{{end}}).ID()
{{- else}}
	a.{{.Name}} = tool.{{.Ref}}().GetByLcuuid(dbItem.{{if .DbFieldName}}{{.DbFieldName}}{{else}}{{.PublicCamelName}}{{end}}).ID()
{{- end}}
{{- end}}
{{- else}}
{{- if and .DbType (ne .DbType .Type)}}
{{- if and (eq .DbType "bytes") (eq .Type "string")}}
	a.{{.Name}} = string(dbItem.{{if .DbFieldName}}{{.DbFieldName}}{{else}}{{.PublicCamelName}}{{end}})
{{- else}}
	a.{{.Name}} = {{.Type}}(dbItem.{{if .DbFieldName}}{{.DbFieldName}}{{else}}{{.PublicCamelName}}{{end}})
{{- end}}
{{- else}}
	a.{{.Name}} = dbItem.{{if .DbFieldName}}{{.DbFieldName}}{{else}}{{.PublicCamelName}}{{end}}
{{- end}}
{{- end}}
{{- end}}
}

{{- $hasHideFields := false}}
{{- range .Fields}}
{{- if .NeedHide}}{{$hasHideFields = true}}{{end}}
{{- end}}
{{- if $hasHideFields}}

// ToLoggable converts {{.PublicName}} to a loggable format, excluding sensitive fields
func (a {{.PublicName}}) ToLoggable() interface{} {
	copied := a
{{- range .Fields}}
{{- if .NeedHide}}
	copied.{{.Name}} = "**HIDDEN**"
{{- end}}
{{- end}}
	return copied
}
{{- end}}

func New{{.PublicName}}Collection(t *tool.Tool) *{{.PublicName}}Collection {
	c := new({{.PublicName}}Collection)
	c.collection = newCollectionBuilder[*{{.PublicName}}]().
		withResourceType(ctrlrcommon.RESOURCE_TYPE_{{ToUpper .Name}}_EN).
		withTool(t).
		withDBItemFactory(func() *metadbmodel.{{.PublicName}} { return new(metadbmodel.{{.PublicName}}) }).
		withCacheItemFactory(func() *{{.PublicName}} { return new({{.PublicName}}) }).
		build()
	return c
}

type {{.PublicName}}Collection struct {
	collection[*{{.PublicName}}, *metadbmodel.{{.PublicName}}]
}