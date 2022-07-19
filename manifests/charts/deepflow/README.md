# DeepFlow Helm Charts


This repository contains [Helm](https://helm.sh/) charts for DeepFlow project.

## Usage

### Prerequisites

- Kubernetes 1.16+
- Helm 3+

[Helm](https://helm.sh) must be installed to use the charts.
Please refer to Helm's [documentation](https://helm.sh/docs/) to get started.

Once Helm is set up properly, add the repo as follows:

```console
helm repo add deepflow https://deepflowys.github.io/deepflow
helm repo udpate deepflow
```

## Helm Charts

You can then run `helm search repo deepflow` to see the charts.

_See [helm repo](https://helm.sh/docs/helm/helm_repo/) for command documentation._

## Installing the Chart

To install the chart with the release name `deepflow`:

```console
helm install deepflow -n deepflow deepflow/deepflow --create-namespace
```

## Uninstalling the Chart

To uninstall/delete the my-release deployment:

```console
helm delete deepflow -n deepflow
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Dependencies

By default this chart installs additional, dependent charts:

- [grafana/grafana](https://github.com/grafana/helm-charts/tree/main/charts/grafana)



## Main values block usage:

### Global

```yaml
  password: 
    mysql: deepflow ## mysql root account password
    grafana: deepflow ## grafana admin account password
  replicas: 1 ## Number of replicas for deepflow-server and clickhouse
  nodePort: ## NodePort that requires a fixed port
    clickhouse: 30900
    deepflowServerIngester: 30033
    deepflowServerGrpc: 30035
    deepflowServerSslGrpc: 30135
    deepflowServerhealthCheck: 30417
  ntpServer: ntp.aliyun.com ## ntp server address, you need to ensure that udp 123 port is available
  allInOneLocalStorage: false   ## Whether to enable allInone local storage, if enabled, the local /opt directory is used to store data by default, ignoring the node affinity check, and is not responsible for any data persistence
```


### Affinity:

The affinity of component. Combine `global.affinity` by 'OR'.

- podAntiAffinityLabelSelector: affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution

  ```yaml
  podAntiAffinityLabelSelector: 
      - labelSelector:
        - key: app #your label key
          operator: In # In、NotIn、Exists、 DoesNotExist
          values: deepflow #your label value, Multiple values separated by commas
        - key: component 
          operator: In
          values: deepflow-server,deepflowys
        topologyKey: "kubernetes.io/hostname"
  ```

- podAntiAffinityTermLabelSelector: affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution

  ```yaml
  podAntiAffinityLabelSelector: 
      - labelSelector:
        - key: app # your label key
          operator: In # In、NotIn、Exists、 DoesNotExist
          values: deepflow # your label value, Multiple values separated by commas
        - key: component 
          operator: In
          values: deepflow-server,deepflowys
        topologyKey: "kubernetes.io/hostname"
  ```

- podAffinityLabelSelector: affinity.podAffinity.requiredDuringSchedulingIgnoredDuringExecution

  ```yaml
    podAffinityLabelSelector:
      - labelSelector:
        - key: app
          operator: In
          values: deepflow
        - key: component
          operator: In
          values: clickhouse
        topologyKey: "kubernetes.io/hostname"
  ```

- podAffinityTermLabelSelector: affinity.podAffinity.preferredDuringSchedulingIgnoredDuringExecution

  ```yaml
    podAffinityTermLabelSelector:
      - topologyKey: kubernetes.io/hostname
        weight: 10
        labelSelector:
          - key: app
            operator: In
            values: deepflow,deepflowys
  ```

- nodeAffinityLabelSelector: affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution

  ```yaml
    nodeAffinityLabelSelector:
      - matchExpressions:
          - key: app
            operator: In
            values: deepflow,deepflowys
  ```

- nodeAffinityTermLabelSelector: affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution

  ```yaml
    nodeAffinityTermLabelSelector:
      - weight: 10
        matchExpressions:
        - key: app
          operator: In
          values: deepflow,deepflowys
  ```

### Storage config

```yaml
  storageConfig:
    type: persistentVolumeClaim  ## persistentVolumeClaim or hostPath,If you use hostPath, you must configure nodeAffinityLabelSelector, otherwise your data will be lost when Pod drifts
    generateType: "{{ if $.Values.global.allInOneLocalStorage }}hostPath{{ else }}{{$.Values.storageConfig.type}}{{end}}" #Please ignore this
    hostPath: /opt/deepflow-clickhouse ## your hostPath path
    persistence: ## volumeClaimTemplates configuration
      - name: clickhouse-path
        accessModes:
        - ReadWriteOnce
        size: 100Gi
        annotations: 
        storageClass: "-"
        # selector:
        #   matchLabels:
        #     app.kubernetes.io/name: clickhouse
      - name: clickhouse-storage-path
        accessModes:
        - ReadWriteOnce
        size: 200Gi
        annotations: 
        storageClass: "-"
        # selector:
        #   matchLabels:
        #     app.kubernetes.io/name: clickhouse
    s3StorageEnabled: false
```