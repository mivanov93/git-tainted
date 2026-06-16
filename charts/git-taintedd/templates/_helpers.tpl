{{/*
Expand the name of the chart.
*/}}
{{- define "git-taintedd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains chart name it will be used as
a full name.
*/}}
{{- define "git-taintedd.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
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
{{- define "git-taintedd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
The container image reference. Tag precedence:
  1. .Values.image.tag (explicit override),
  2. .Chart.AppVersion (the chart's pinned app version; CI bumps this per release).
*/}}
{{- define "git-taintedd.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "git-taintedd.labels" -}}
helm.sh/chart: {{ include "git-taintedd.chart" . }}
{{ include "git-taintedd.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: git-tainted
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels — the stable identity used by Service/Deployment selectors.
Must NOT include version or any value that changes across upgrades.
*/}}
{{- define "git-taintedd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "git-taintedd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The name of the service account to use.
*/}}
{{- define "git-taintedd.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "git-taintedd.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The Secret name to reference for sensitive GT_* values.
Prefers an externally-managed (BYO) secret over the chart-created one.
*/}}
{{- define "git-taintedd.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "git-taintedd.fullname" . -}}
{{- end -}}
{{- end }}

{{/*
hasSecretData — true when the chart should reference a Secret at all, i.e. either
an existingSecret is named, or at least one of the four sensitive values is set.
Used to decide whether to emit the Secret and whether to add it to envFrom.
*/}}
{{- define "git-taintedd.hasSecretData" -}}
{{- $d := .Values.secrets.data -}}
{{- if .Values.secrets.existingSecret -}}
true
{{- else if or $d.mysqlDSN $d.apiKeys $d.apiKeysSHA256 $d.basicAuth -}}
true
{{- end -}}
{{- end }}

{{/*
The PVC name used by the sqlite data volume.
*/}}
{{- define "git-taintedd.pvcName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "git-taintedd.fullname" .) -}}
{{- end -}}
{{- end }}
