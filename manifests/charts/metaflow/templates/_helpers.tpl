{{/*
Expand the name of the chart.
*/}}
{{- define "metaflow.name" -}}
{{- $metaflowChartName := "metaflow" }}
{{- default $metaflowChartName .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "metaflow.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $metaflowChartName := "metaflow" }}
{{- $name := default $metaflowChartName .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "metaflow.chart" -}}
{{- $metaflowChartName := "metaflow" }}
{{- printf "%s-%s" $metaflowChartName .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "metaflow.labels" -}}
helm.sh/chart: {{ include "metaflow.chart" . }}
{{ include "metaflow.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "metaflow.selectorLabels" -}}
app: metaflow
app.kubernetes.io/name: {{ include "metaflow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "metaflow-server.labels" -}}
helm.sh/chart: {{ include "metaflow.chart" . }}
{{ include "metaflow.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "metaflow-server.selectorLabels" -}}
app: metaflow
component: metaflow-server
app.kubernetes.io/name: {{ include "metaflow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "metaflow-app.labels" -}}
helm.sh/chart: {{ include "metaflow.chart" . }}
{{ include "metaflow-app.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "metaflow-app.selectorLabels" -}}
app: metaflow
component: metaflow-app
app.kubernetes.io/name: {{ include "metaflow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
