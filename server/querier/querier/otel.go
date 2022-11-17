package querier

import (
	"context"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	otelTrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"strings"
)

func initTraceProvider(endpoint string) *otelTrace.TracerProvider {
	ctx := context.Background()

	//应该被携带到span中的环境信息（进程名、主机名、服务名等）
	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithAttributes(
			// the service name used to display traces in backends
			semconv.ServiceNameKey.String("deepflow-server-querier"),
			// env=running environment
			semconv.DeploymentEnvironmentKey.String("namespace-deepflow"),
		),
	)

	if err != nil {
		log.Error(err)
		return nil
	}
	urlPath := ""
	if strings.Contains(endpoint, "http://") {
		endpointSplit := strings.Split(endpoint, "/")
		endpoint = endpointSplit[2]
		if len(endpointSplit) > 2 {
			urlPath = "/" + strings.Join(endpointSplit[3:], "/")
		}
	}
	//创建OtlpExporter，并通过默认的Exporter做数据导出
	oltpExporter, err := otlptrace.New(ctx,
		otlptracehttp.NewClient(
			otlptracehttp.WithEndpoint(endpoint),
			otlptracehttp.WithInsecure(),
			otlptracehttp.WithURLPath(urlPath),
		))

	if err != nil {
		log.Fatalf("creating oltp exporter: %v", err)
	}
	tp := otelTrace.NewTracerProvider(
		// pass exporter
		otelTrace.WithBatcher(oltpExporter),
		// pass resource
		otelTrace.WithResource(res),
		// option=获取所有采样信息
		otelTrace.WithSampler(otelTrace.AlwaysSample()),
	)

	// 全局设置同一个 traceprovider，需要根据实际情况，如果是微服务，需要每个微服务自行初始化tp
	otel.SetTracerProvider(tp)

	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{}))

	return tp
}
