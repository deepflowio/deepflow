/**
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package model

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

const (
	// 35GB
	totalDataSize = 35 * 1024 * 1024 * 1024
	// 15w
	totalRuns = 150000
	// 35g/15w
	singleDataSize = totalDataSize / totalRuns
)

var (
	// To make the data size to 245760, we need to repeat the baseYAMLData 35 times
	repeatTimes = 35
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

const baseYAMLData = `
apiVersion: v1
data:
  app.yaml: |
    app:
      http_request_timeout: 600
      http_response_timeout: 600
      listen-port: 20418
      log-file: /var/log/deepflow/app.log
      log-level: info
      controller:
        host: deepflow-server
        port: 20417
        timeout: 60
      querier:
        host: deepflow-server
        port: 20416
        timeout: 60
      spec:
        allow_multiple_trace_ids_in_tracing_result: false
        call_apm_api_to_supplement_trace: false
        host_clock_offset_us: 10000
        l7_tracing_limit: 1000
        network_delay_us: 50000
  random_payload: |
    RANDOM_PAYLOAD_PLACEHOLDER
  server.yaml: |
    log-file: /var/log/deepflow/server.log
    log-level: info
    controller:
      agent-cmd-timeout: 30
      all-agent-connect-to-nat-ip: false
      billing-method: license
      election-name: deepflow-server
      election-namespace: deepflow
      grpc-max-message-length: 104857600
      grpc-node-port: 30035
      grpc-port: 20035
      listen-node-port: 30417
      listen-port: 20417
      log-file: /var/log/deepflow/server.log
      log-level: info
      no-ip-overlapping: false
      pod-cluster-internal-ip-to-ingester: 0
      reporting-disabled: true
      clickhouse:
        database: flow_tag
        endpoint-tcp-port-name: tcp-port
        host: deepflow-clickhouse
        port: 9000
        timeout: 60
        user-name: default
        user-password: passwd
      df-web-service:
        enabled: true
        host: df-web
        port: 20825
        timeout: 30
      fpermit:
        enabled: true
        host: fpermit
        port: 20823
        timeout: 30
      genesis:
        aging_time: 86400
        data_persistence_interval: 60
        exclude_ip_ranges:
        host_ips:
        local_ip_ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 169.254.0.0/15
        - 224.0.0.0-240.255.255.255
        queue_length: 1000
        single_vpc_mode: false
        vinterface_aging_time: 300
      ingester-api:
        node-port: 30106
        port: 20106
        timeout: 60
      manager:
        cloud_config_check_interval: 60
        task:
          resource_recorder_interval: 60
          cloud:
            aliyun_region_name: cn-beijing
            debug_enabled: false
            genesis_default_vpc: default_vpc
            hostname_to_ip_file: /etc/hostname_to_ip.csv
            kubernetes_gather_interval: 60
          recorder:
            cache_refresh_interval: 60
            deleted_resource_clean_interval: 24
            deleted_resource_retention_time: 168
            resource_max_id_0: 64000
            resource_max_id_1: 499999
      monitor:
        auto_rebalance_vtap: true
        exception_time_frame: 2592000
        health_check_handle_channel_len: 1000
        health_check_interval: 60
        license_check_interval: 60
        rebalance_check_interval: 300
        vtap_check_interval: 60
        ingester-load-balancing-strategy:
          algorithm: by-ingested-data
          data-duration: 86400
          rebalance-interval: 3600
        vtap_auto_delete:
          enabled: false
        warrant:
          host: warrant
          port: 20413
          timeout: 30
      mysql:
        database: deepflow
        host: mysql
        port: 30130
        proxy-host:
        proxy-port:
        timeout: 30
        user-name: root
        user-password: passwd
      prometheus:
        data_clean_interval: 40
        encoder_cache_refresh_interval: 3600
        synchronizer_cache_refresh_interval: 60
      redis:
        cluster_enabled: false
        dimension_resource_database: 2
        enabled: true
        host: ['redis']
        password: passwd
        port: 6379
        resource_api_database: 1
        timeout: 30
      spec:
        az_max_per_server: 10
        data_source_ext_metrics_interval: 10
        data_source_max: 25
        data_source_prometheus_interval: 10
        data_source_retention_time_max: 24000
        vtap_group_max: 1000
        vtap_max_per_group: 10000
      statsd:
        enabled: true
      tagrecorder:
        mysql_batch_size: 1000
      trisolaris:
        clear-kubernetes-time: 600
        domain-auto-register: true
        max-escape-seconds: 3600
        node-type: master
        platform-vips:
        region-domain-prefix: master-
        trident-type-for-unknow-vtap: 0
        tsdb_ip:
        chrony:
          host: K8S_NODE_IP_FOR_DEEPFLOW
          port: 123
          timeout: 1
    ingester:
      ckdb:
        cluster-name:
        endpoint-tcp-port-name: tcp-port
        external: false
        host: deepflow-clickhouse
        port: 9000
        storage-policy:
        type: clickhouse
      ckdb-auth:
        password: passwd
        username: default
    querier:
      language: ch
      listen-port: 20416
      log-file: /var/log/deepflow/server.log
      log-level: info
      clickhouse:
        database: flow_tag
        host: deepflow-clickhouse
        port: 9000
        timeout: 60
        user-name: default
        user-password: passwd
      profile:
        flame_query_limit: 1000000
        listen-port: 20419
        querier:
          host: deepflow-server
          port: 20416
      trace-map:
        batch_traces_count_max: 1000
        debug_sql_len_max: 1000
        max_trace_per_iteration: 100000
        trace_id_query_iterations: 8
        trace_query_delta: 300
        write_batch_size: 1000
        write_interval: 60
kind: ConfigMap
metadata:
  annotations:
    meta.helm.sh/release-name: deepflow
    meta.helm.sh/release-namespace: deepflow
  creationTimestamp: "2025-12-10T20:58:36Z"
  labels:
    app: deepflow
    app.kubernetes.io/instance: deepflow
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: deepflow
    app.kubernetes.io/version: 6.1.6
    helm.sh/chart: deepflow-0.1.063
  name: deepflow
  namespace: deepflow
  resourceVersion: "75897137"
  uid: aba03a5f-e015-4be6-b168-28da0bbef48f
`

func BenchmarkAutoCompressedBytes_Scan(b *testing.B) {
	rand.Seed(time.Now().UnixNano())

	fmt.Printf("测试配置:\n")
	fmt.Printf("  总数据量: %d GB\n", totalDataSize/(1024*1024*1024))
	fmt.Printf("  总测试次数: %d\n", totalRuns)
	fmt.Printf("  单次数据大小: %d Bytes (约 %.2f KB)\n",
		singleDataSize, float64(singleDataSize)/1024)

	// Adjust this to get the desired compression ratio, aiming for 20-30%
	// A larger random part leads to a lower compression ratio (higher final percentage).
	randomDataSize := singleDataSize / 4 // Start with 25% random data
	yamlPartSize := singleDataSize - randomDataSize

	randomPayload := randStringRunes(randomDataSize)

	var sb strings.Builder
	for sb.Len() < yamlPartSize {
		sb.WriteString(baseYAMLData)
	}
	yamlPart := sb.String()
	if len(yamlPart) > yamlPartSize {
		yamlPart = yamlPart[:yamlPartSize]
	}

	// Embed the random payload
	largeYAMLData := strings.Replace(yamlPart, "RANDOM_PAYLOAD_PLACEHOLDER", randomPayload, 1)
	uncompressedSize := len(largeYAMLData)

	// compress data
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write([]byte(largeYAMLData))
	w.Close()
	compressedData := buf.Bytes()
	compressedSize := len(compressedData)

	// print compression ratio
	compressionRatio := float64(compressedSize) / float64(uncompressedSize) * 100
	fmt.Printf("\n压缩率验证:\n")
	fmt.Printf("  原始数据大小: %d bytes (%.2f KB)\n", uncompressedSize, float64(uncompressedSize)/1024)
	fmt.Printf("  压缩后大小: %d bytes (%.2f KB)\n", compressedSize, float64(compressedSize)/1024)
	fmt.Printf("  压缩率: %.2f%%\n", compressionRatio)

	if compressionRatio < 20 || compressionRatio > 30 {
		fmt.Printf("  ⚠️  警告: 压缩率 %.2f%% 不在预期的20-30%%范围内\n", compressionRatio)
	} else {
		fmt.Printf("  ✓ 压缩率在预期的20-30%%范围内\n")
	}

	b.ResetTimer()
	b.SetBytes(int64(uncompressedSize))

	for i := 0; i < b.N; i++ {
		var a AutoCompressedBytes
		if err := a.Scan(compressedData); err != nil {
			b.Fatal(err)
		}
	}
}
