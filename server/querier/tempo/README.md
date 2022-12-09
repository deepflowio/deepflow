[protobuf](https://github.com/grafana/tempo/blob/main/pkg/tempopb/trace/v1/trace.pb.go)

- Response of tempo api:
```
{
    // The resource for the spans in this message.
    // If this field is not set then no resource info is known.
    "resource":{
        "attributes":[
            {
                "key":"service.name",
                "value":{
                    "stringValue":"xxx"
                }
            },
            {
                "key":"xxx",
                "value":{
                    "stringValue":"xxx"
                }
            }
            ...
        ]
    },
    // The instrumentation library information for the spans in this message.
    // Semantically when InstrumentationLibrary isn't set, it is equivalent with
    // an empty instrumentation library name (unknown).
    "instrumentationLibrarySpans":{
        "instrumentationLibrary":{
            "name":"xxx",
            "version":"xxx"
        },
        "spans":[
            {
                // A unique identifier for a trace. All spans from the same trace share
                // the same `trace_id`. The ID is a 16-byte array. An ID with all zeroes
                // is considered invalid.
                //
                // This field is semantically required. Receiver should generate new
                // random trace_id if empty or invalid trace_id was received.
                //
                // This field is required.
                "traceId":"WTqtr7BlQGzwAyzVaQhnqA=                
                // A unique identifier for a span within a trace, assigned when the span
                // is created. The ID is an 8-byte array. An ID with all zeroes is considered
                // invalid.
                //
                // This field is semantically required. Receiver should generate new
                // random span_id if empty or invalid span_id was received.
                //
                // This field is required.
                "spanId":"thJE5jAyatg                
                // The `span_id` of this span's parent span. If this is a root span, then this
                // field must be empty. The ID is an 8-byte array.
                "parentSpanId":"AdJrrVtdU9g                
                // A description of the span's operation.
                //
                // For example, the name can be a qualified method name or a file name
                // and a line number where the operation is called. A best practice is to use
                // the same display name at the same call point in an application.
                // This makes it easier to correlate spans in different traces.
                //
                // This field is semantically required to be set to non-empty string.
                // Empty value is equivalent to an unknown span name.
                //
                // This field is required.
                "name":"proxy0.getStoc                
                // Distinguishes between spans generated in a particular context. For example,
                // two spans with the same name may be distinguished using `CLIENT` (caller)
                // and `SERVER` (callee) to identify queueing latency associated with the span.
                "kind":"SPAN_KIND_INTERNA                
                "startTimeUnixNano":"1668391014669291592",
                "endTimeUnixNano":"166839101466938600                
                // attributes is a collection of key/value pairs. Note, global attributes
                // like server name can be set using the resource API. Examples of attributes:
                //
                //     "/http/user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
                //     "/http/server_latency": 300
                //     "abc.com/myattribute": true
                //     "abc.com/score": 10.239
                //
                // The OpenTelemetry API specification further restricts the allowed value types:
                // https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/common/common.md#attributes
                // Attribute keys MUST be unique (it is not allowed to have more than one
                // attribute with the same key).
                "attributes":[
                    {
                        "key":"xxx",
                        "value":{
                            "stringValue":"xxx"
                        }
                    },
                    ...
                ],
                "status":{
                }
            }
        ]
    }
}
```