# Construct From Source

In order to improve the performance of receiving Prometheus `remote_write` data, we precompiled a set of pb.go files and put them here, and made several performance optimizations.

In order to allow other logic in deepflow-server (such as querier) to continue to use the original pb.go file, we modified the package in the code optimized here to avoid conflicts with the original structure.

```bash
wget https://raw.githubusercontent.com/prometheus/prometheus/main/prompb/remote.proto
wget https://raw.githubusercontent.com/prometheus/prometheus/main/prompb/remote.pb.go
wget https://raw.githubusercontent.com/prometheus/prometheus/main/prompb/types.proto
wget https://raw.githubusercontent.com/prometheus/prometheus/main/prompb/types.pb.go

# change package from `prometheus` to `prometheus_deepflow`
sed -i 's/\<prometheus\>/prometheus_deepflow/g' ./*.proto ./*.pb.go
```

# Optimizations

We provide a `ResetWithBufferReserved()` method, so that the `WriteRequest` structure can reuse its internal `TimeSeries` and `Labels` array memory during frequent unmarshall.

In addition, when deserializing the string in Label, we use the mechanism in the `unsafeBytesToString()` method to avoid memory allocation. Therefore, when using this file, <mark>please note that neither the `Name` nor the `Value` in the `Label` hold actual memory</mark>.
