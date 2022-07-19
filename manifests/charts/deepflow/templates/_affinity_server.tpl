{{/* affinity - https://kubernetes.io/docs/concepts/configuration/assign-pod-node/ */}}

{{- define "serverNodeaffinity" }}
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    {{- include "serverNodeAffinityRequiredDuringScheduling" . }}
    preferredDuringSchedulingIgnoredDuringExecution:
    {{- include "serverNodeAffinityPreferredDuringScheduling" . }}
{{- end }}

{{- define "serverNodeAffinityRequiredDuringScheduling" }}
    {{- if or .Values.server.nodeAffinityLabelSelector .Values.global.nodeAffinityLabelSelector }}
      nodeSelectorTerms:
      {{- range $matchExpressionsIndex, $matchExpressionsItem := .Values.server.nodeAffinityLabelSelector }}
        - matchExpressions:
        {{- range $Index, $item := $matchExpressionsItem.matchExpressions }}
          - key: {{ $item.key }}
            operator: {{ $item.operator }}
            {{- if $item.values }}
            values:
            {{- $vals := split "," $item.values }}
            {{- range $i, $v := $vals }}
            - {{ $v | quote }}
            {{- end }}
            {{- end }}
          {{- end }}
      {{- end }}
      {{- range $matchExpressionsIndex, $matchExpressionsItem := .Values.global.nodeAffinityLabelSelector }}
        - matchExpressions:
        {{- range $Index, $item := $matchExpressionsItem.matchExpressions }}
          - key: {{ $item.key }}
            operator: {{ $item.operator }}
            {{- if $item.values }}
            values:
            {{- $vals := split "," $item.values }}
            {{- range $i, $v := $vals }}
            - {{ $v | quote }}
            {{- end }}
            {{- end }}
          {{- end }}
      {{- end }}
    {{- end }}
{{- end }}

{{- define "serverNodeAffinityPreferredDuringScheduling" }}
    {{- range $weightIndex, $weightItem := .Values.server.nodeAffinityTermLabelSelector }}
    - weight: {{ $weightItem.weight }}
      preference:
        matchExpressions:
      {{- range $Index, $item := $weightItem.matchExpressions }}
        - key: {{ $item.key }}
          operator: {{ $item.operator }}
          {{- if $item.values }}
          values:
          {{- $vals := split "," $item.values }}
          {{- range $i, $v := $vals }}
          - {{ $v | quote }}
          {{- end }}
          {{- end }}
      {{- end }}
    {{- end }}
    {{- range $weightIndex, $weightItem := .Values.global.nodeAffinityTermLabelSelector }}
    - weight: {{ $weightItem.weight }}
      preference:
        matchExpressions:
      {{- range $Index, $item := $weightItem.matchExpressions }}
        - key: {{ $item.key }}
          operator: {{ $item.operator }}
          {{- if $item.values }}
          values:
          {{- $vals := split "," $item.values }}
          {{- range $i, $v := $vals }}
          - {{ $v | quote }}
          {{- end }}
          {{- end }}
      {{- end }}
    {{- end }}
{{- end }}


{{- define "serverPodAffinity" }}
{{- if or .Values.server.podAffinityLabelSelector .Values.server.podAffinityTermLabelSelector}}
  podAffinity:
    {{- if .Values.server.podAffinityLabelSelector }}
    requiredDuringSchedulingIgnoredDuringExecution:
    {{- include "serverPodAffinityRequiredDuringScheduling" . }}
    {{- end }}
    {{- if or .Values.server.podAffinityTermLabelSelector}}
    preferredDuringSchedulingIgnoredDuringExecution:
    {{- include "serverPodAffinityPreferredDuringScheduling" . }}
    {{- end }}
{{- end }}
{{- end }}

{{- define "serverPodAffinityRequiredDuringScheduling" }}
    {{- range $labelSelector, $labelSelectorItem := .Values.server.podAffinityLabelSelector }}
    - labelSelector:
        matchExpressions:
      {{- range $index, $item := $labelSelectorItem.labelSelector }}
        - key: {{ $item.key }}
          operator: {{ $item.operator }}
          {{- if $item.values }}
          values:
          {{- $vals := split "," $item.values }}
          {{- range $i, $v := $vals }}
          - {{ $v | quote }}
          {{- end }}
          {{- end }}
        {{- end }}
      topologyKey: {{ $labelSelectorItem.topologyKey }}
    {{- end }}
    {{- range $labelSelector, $labelSelectorItem := .Values.global.podAffinityLabelSelector }}
    - labelSelector:
        matchExpressions:
      {{- range $index, $item := $labelSelectorItem.labelSelector }}
        - key: {{ $item.key }}
          operator: {{ $item.operator }}
          {{- if $item.values }}
          values:
          {{- $vals := split "," $item.values }}
          {{- range $i, $v := $vals }}
          - {{ $v | quote }}
          {{- end }}
          {{- end }}
        {{- end }}
      topologyKey: {{ $labelSelectorItem.topologyKey }}
    {{- end }}
{{- end }}

{{- define "serverPodAffinityPreferredDuringScheduling" }}
    {{- range $labelSelector, $labelSelectorItem := .Values.server.podAffinityTermLabelSelector }}
    - podAffinityTerm:
        labelSelector:
          matchExpressions:
      {{- range $index, $item := $labelSelectorItem.labelSelector }}
          - key: {{ $item.key }}
            operator: {{ $item.operator }}
            {{- if $item.values }}
            values:
            {{- $vals := split "," $item.values }}
            {{- range $i, $v := $vals }}
            - {{ $v | quote }}
            {{- end }}
            {{- end }}
        {{- end }}
        topologyKey: {{ $labelSelectorItem.topologyKey }}
      weight:  {{ $labelSelectorItem.weight }}
    {{- end }}
    {{- range $labelSelector, $labelSelectorItem := .Values.global.podAffinityTermLabelSelector }}
    - podAffinityTerm:
        labelSelector:
          matchExpressions:
      {{- range $index, $item := $labelSelectorItem.labelSelector }}
          - key: {{ $item.key }}
            operator: {{ $item.operator }}
            {{- if $item.values }}
            values:
            {{- $vals := split "," $item.values }}
            {{- range $i, $v := $vals }}
            - {{ $v | quote }}
            {{- end }}
            {{- end }}
        {{- end }}
        topologyKey: {{ $labelSelectorItem.topologyKey }}
      weight:  {{ $labelSelectorItem.weight }}
    {{- end }}
{{- end }}

{{- define "serverPodAntiAffinity" }}
{{- if or .Values.server.podAntiAffinityLabelSelector .Values.server.podAntiAffinityTermLabelSelector}}
  podAntiAffinity:
    {{- if .Values.server.podAntiAffinityLabelSelector }}
    requiredDuringSchedulingIgnoredDuringExecution:
    {{- include "serverPodAntiAffinityRequiredDuringScheduling" . }}
    {{- end }}
    {{- if or .Values.server.podAntiAffinityTermLabelSelector}}
    preferredDuringSchedulingIgnoredDuringExecution:
    {{- include "serverPodAntiAffinityPreferredDuringScheduling" . }}
    {{- end }}
{{- end }}
{{- end }}

{{- define "serverPodAntiAffinityRequiredDuringScheduling" }}
    {{- range $labelSelectorIndex, $labelSelectorItem := .Values.server.podAntiAffinityLabelSelector }}
    - labelSelector:
        matchExpressions:
      {{- range $index, $item := $labelSelectorItem.labelSelector }}
        - key: {{ $item.key }}
          operator: {{ $item.operator }}
          {{- if $item.values }}
          values:
          {{- $vals := split "," $item.values }}
          {{- range $i, $v := $vals }}
          - {{ $v | quote }}
          {{- end }}
          {{- end }}
        {{- end }}
      topologyKey: {{ $labelSelectorItem.topologyKey }}
    {{- end }}
    {{- range $labelSelectorIndex, $labelSelectorItem := .Values.global.podAntiAffinityLabelSelector }}
    - labelSelector:
        matchExpressions:
      {{- range $index, $item := $labelSelectorItem.labelSelector }}
        - key: {{ $item.key }}
          operator: {{ $item.operator }}
          {{- if $item.values }}
          values:
          {{- $vals := split "," $item.values }}
          {{- range $i, $v := $vals }}
          - {{ $v | quote }}
          {{- end }}
          {{- end }}
        {{- end }}
      topologyKey: {{ $labelSelectorItem.topologyKey }}
    {{- end }}
{{- end }}

{{- define "serverPodAntiAffinityPreferredDuringScheduling" }}
    {{- range $labelSelectorIndex, $labelSelectorItem := .Values.server.podAntiAffinityTermLabelSelector }}
    - podAffinityTerm:
        labelSelector:
          matchExpressions:
      {{- range $index, $item := $labelSelectorItem.labelSelector }}
          - key: {{ $item.key }}
            operator: {{ $item.operator }}
            {{- if $item.values }}
            values:
            {{- $vals := split "," $item.values }}
            {{- range $i, $v := $vals }}
            - {{ $v | quote }}
            {{- end }}
            {{- end }}
        {{- end }}
        topologyKey: {{ $labelSelectorItem.topologyKey }}
      weight: {{ $labelSelectorItem.weight }}
    {{- end }}
    {{- range $labelSelectorIndex, $labelSelectorItem := .Values.global.podAntiAffinityTermLabelSelector }}
    - podAffinityTerm:
        labelSelector:
          matchExpressions:
      {{- range $index, $item := $labelSelectorItem.labelSelector }}
          - key: {{ $item.key }}
            operator: {{ $item.operator }}
            {{- if $item.values }}
            values:
            {{- $vals := split "," $item.values }}
            {{- range $i, $v := $vals }}
            - {{ $v | quote }}
            {{- end }}
            {{- end }}
        {{- end }}
        topologyKey: {{ $labelSelectorItem.topologyKey }}
      weight: {{ $labelSelectorItem.weight }}
    {{- end }}
{{- end }}