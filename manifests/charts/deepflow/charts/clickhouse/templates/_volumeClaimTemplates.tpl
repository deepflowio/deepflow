{{- /* PVC templates */ -}}
{{- define "persistentVolumeClaim" -}}
{{- range $index, $volume := .Values.storageConfig.persistence }}
- kind: PersistentVolumeClaim
  apiVersion: v1
  metadata:
    name: {{ $volume.name }}
    annotations:
      {{- toYaml $volume.annotations | nindent 8 }}
  spec:
    accessModes:
      {{- toYaml $volume.accessModes | nindent 8 }}
    resources:
      requests:
        storage: {{ $volume.size | quote }}
    {{- if  (tpl $volume.storageClass $) }}
    storageClassName: {{ tpl $volume.storageClass $ | quote }}
    {{- end }}
    {{- if $volume.selector }}
    selector:
      {{- toYaml $volume.selector | nindent 8 }}
    {{- end }}
{{- end }}
{{- end }}