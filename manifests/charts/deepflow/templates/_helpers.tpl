{{/*
Expand the name of the chart.
*/}}
{{- define "deepflow.name" -}}
{{- $deepflowChartName := "deepflow" }}
{{- default $deepflowChartName .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "deepflow.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $deepflowChartName := "deepflow" }}
{{- $name := default $deepflowChartName .Values.nameOverride }}
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
{{- define "deepflow.chart" -}}
{{- $deepflowChartName := "deepflow" }}
{{- printf "%s-%s" $deepflowChartName .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "deepflow.labels" -}}
helm.sh/chart: {{ include "deepflow.chart" . }}
{{ include "deepflow.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "deepflow.selectorLabels" -}}
app: deepflow
app.kubernetes.io/name: {{ include "deepflow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "deepflow-server.labels" -}}
helm.sh/chart: {{ include "deepflow.chart" . }}
{{ include "deepflow.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "deepflow-server.selectorLabels" -}}
app: deepflow
component: deepflow-server
app.kubernetes.io/name: {{ include "deepflow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "deepflow-app.labels" -}}
helm.sh/chart: {{ include "deepflow.chart" . }}
{{ include "deepflow-app.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "deepflow-app.selectorLabels" -}}
app: deepflow
component: deepflow-app
app.kubernetes.io/name: {{ include "deepflow.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
