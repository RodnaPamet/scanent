{{/* The chart's name, and the name every object of a release starts with. */}}
{{- define "scanent.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "scanent.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 52 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "scanent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "scanent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "scanent.labels" -}}
{{ include "scanent.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* The image: by digest when one is given, otherwise by tag (the chart's appVersion when none is). */}}
{{- define "scanent.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{- define "scanent.configMapName" -}}
{{- .Values.existingConfigMap | default (printf "%s-config" (include "scanent.fullname" .)) -}}
{{- end -}}

{{/* At most 63 characters: a Service name is a DNS label, and the scanner's HTTPS_PROXY host is this name. */}}
{{- define "scanent.proxyName" -}}
{{- printf "%s-egress-proxy" (include "scanent.fullname" . | trunc 50 | trimSuffix "-") -}}
{{- end -}}

{{/* "true" when the inline configuration delivers each run somewhere besides the output volume. */}}
{{- define "scanent.deliversElsewhere" -}}
{{- $elsewhere := false -}}
{{- if hasKey .Values.config "outputs" -}}
{{- range .Values.config.outputs -}}
{{- if or (eq (toString .kind) "inflect") (eq (toString .kind) "stdout") -}}
{{- $elsewhere = true -}}
{{- end -}}
{{- end -}}
{{- else if hasKey .Values.config "inflect" -}}
{{- $elsewhere = true -}}
{{- end -}}
{{- $elsewhere -}}
{{- end -}}

{{/*
What the chart refuses to install, each with the reason. Included once, by the
CronJob, so a refused release renders nothing.
*/}}
{{- define "scanent.validate" -}}
{{- if and (empty .Values.config) (empty .Values.existingConfigMap) -}}
{{- fail "scanent: set `config` (the scanner configuration) or `existingConfigMap`. There is nothing to scan without one." -}}
{{- end -}}
{{- if and (not (empty .Values.config)) (not (empty .Values.existingConfigMap)) -}}
{{- fail "scanent: set `config` or `existingConfigMap`, not both. One of them would be silently ignored." -}}
{{- end -}}
{{- if and (not (empty .Values.secrets.files)) (empty .Values.secrets.existingSecret) -}}
{{- fail "scanent: `secrets.files` lists credentials but `secrets.existingSecret` is empty. Create the Secret and name it; the chart never creates one." -}}
{{- end -}}
{{- if and (eq .Values.output.type "existingClaim") (empty .Values.output.existingClaim) -}}
{{- fail "scanent: `output.type` is existingClaim but `output.existingClaim` is empty." -}}
{{- end -}}
{{- if eq .Values.output.type "emptyDir" -}}
{{- if ne (include "scanent.deliversElsewhere" .) "true" -}}
{{- fail "scanent: `output.type: emptyDir` keeps nothing after the pod ends, and the configuration given in `config` delivers each run nowhere else (no inflect or stdout output). Use pvc or existingClaim. With `existingConfigMap` the chart cannot read the outputs, so emptyDir is refused there too." -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.networkPolicy.flavor "cilium") (empty .Values.egress.fqdns) -}}
{{- fail "scanent: `networkPolicy.flavor: cilium` with an empty `egress.fqdns` would deny every host, and the scanner could read nothing. List the hosts from `scanent hosts --config config.json`." -}}
{{- end -}}
{{- if and .Values.egressProxy.enabled (empty .Values.egress.fqdns) -}}
{{- fail "scanent: `egressProxy.enabled` with an empty `egress.fqdns` would refuse every host, and the scanner could read nothing. List the hosts from `scanent hosts --config config.json`." -}}
{{- end -}}
{{- if and .Values.egressProxy.enabled (eq .Values.networkPolicy.flavor "cilium") -}}
{{- fail "scanent: `egressProxy.enabled` and `networkPolicy.flavor: cilium` both limit the scanner to `egress.fqdns`. Choose one." -}}
{{- end -}}
{{- if and .Values.egressProxy.enabled (or .Values.proxy.httpsProxy .Values.networkPolicy.proxy.cidr) -}}
{{- fail "scanent: `egressProxy.enabled` sets the scanner's proxy to the bundled one. Remove `proxy.httpsProxy` and `networkPolicy.proxy.cidr`, or disable the bundled proxy." -}}
{{- end -}}
{{- if and (not .Values.egressProxy.enabled) (not (empty .Values.egressProxy.privateCidrs)) -}}
{{- fail "scanent: `egressProxy.privateCidrs` is set but `egressProxy.enabled` is not. The ranges are the bundled proxy's; without it they do nothing." -}}
{{- end -}}
{{- if and (eq .Values.networkPolicy.flavor "cilium") .Values.networkPolicy.proxy.cidr -}}
{{- fail "scanent: `networkPolicy.proxy.cidr` is for the kubernetes flavor. Behind a forward proxy the proxy decides the hosts; use `flavor: kubernetes`." -}}
{{- end -}}
{{- end -}}

{{/* The pod-level security context every pod of the chart runs with. */}}
{{- define "scanent.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 1000
runAsGroup: 1000
fsGroup: 1000
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* The container-level security context every container of the chart runs with. */}}
{{- define "scanent.containerSecurityContext" -}}
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
privileged: false
capabilities:
  drop:
    - ALL
{{- end -}}

{{/*
Egress to the cluster's DNS, as NetworkPolicy rules: the DNS pods, and any
address in `networkPolicy.dns.cidrs` (NodeLocal DNSCache answers on a node
address, which no pod selector matches).
*/}}
{{- define "scanent.dnsEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ .Values.networkPolicy.dns.namespace }}
      podSelector:
        matchLabels:
          {{- toYaml .Values.networkPolicy.dns.podLabels | nindent 10 }}
    {{- range .Values.networkPolicy.dns.cidrs }}
    - ipBlock:
        cidr: {{ . }}
    {{- end }}
  ports:
    - protocol: UDP
      port: {{ .Values.networkPolicy.dns.port }}
    - protocol: TCP
      port: {{ .Values.networkPolicy.dns.port }}
{{- end -}}

{{/* Egress on TCP 443 to public addresses: no private, shared, link-local or metadata range. */}}
{{- define "scanent.publicHttpsEgress" -}}
- to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
          - 100.64.0.0/10
          - 169.254.0.0/16
    - ipBlock:
        cidr: ::/0
        except:
          - fc00::/7
          - fe80::/10
  ports:
    - protocol: TCP
      port: 443
{{- end -}}
