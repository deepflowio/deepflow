# Construct From Source

```bash
wget https://raw.githubusercontent.com/prometheus/prometheus/main/prompb/remote.proto
wget https://raw.githubusercontent.com/prometheus/prometheus/main/prompb/remote.pb.go
wget https://raw.githubusercontent.com/prometheus/prometheus/main/prompb/types.proto
wget https://raw.githubusercontent.com/prometheus/prometheus/main/prompb/types.pb.go

sed -i 's/\<prometheus\>/prometheus_deepflow/g' ./*.proto ./*.pb.go
```
