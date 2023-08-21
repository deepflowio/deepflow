# How to profile server

## [go pprof tool](https://pkg.go.dev/net/http/pprof) is used to profile deepflow-server once
- Start the pprof service
  - configuration open:
  ```
  profiler: true
  ```
  - if it is not configured, you can also use the command to open
    -  `deepflow-ctl -i <server pod IP> ingester profiler on`
- Get pprof CPU profile(heap/mutex/block/trace profile is also similar) information and generate graphs for analysis
  - you should install `golang 1.18+` and `graphviz` for analyze
    - for example on CentOS, `yum install golang -y; yum install graphviz -y`
  - get the cpu profile and generate graphs to show
    - `go tool pprof http://<server pod IP>:9526/debug/pprof/profile`
      - if not install `golang 1.18+`, you should use `curl` to get profile and name it 'cpu.pprof'
        - `curl http://<server pod IP>:9526/debug/pprof/profile -o cpu.pprof`
        - `go tool pprof cpu.pprof`, do it on another machine which installed `golang 1.18+`
    - suggest execute `pdf` or `svg` to outputs a graph in PDF/SVG format.
- You should close pprof service, if it is no longer used
  - if you open with the command, close with the command
    - `deepflow-ctl -i <server pod IP> ingester profiler off`
  - if it is configured `profiler: true`, configuration closed, `profiler: false`

## [Continuous Profile with pyroscope](https://github.com/grafana/pyroscope) is used to profile deepflow-server continuous
- Install pyroscope in K8S to receive and display continuous profile data
  ```
  helm repo add pyroscope-io https://pyroscope-io.github.io/helm-chart
  helm install pyroscope pyroscope-io/pyroscope
  ```
  - by default installs into the `default` namespace and create service `pyroscope`
  - you should modify the service type of ClusterIP to NodePort for access
    - `kubectl edit svc pyroscope`
      - modify `type: ClusterIP` to `type: NodePort`
- Start the deepflow-server continuous profiler
  - configuration open:
  ```
  continuous-profiler:
    enabled: true
    server-addr: http://pyroscope.default:4040/
  ```
- Show continuous profiler
  - get service `pyroscope` NodePort
    - `kubectl get svc | grep pyroscope`, get `3xxxx` port
  - web browser access: `http://<pyroscope NodeIP>:<NodePort>/`

