package tempo

import (
	"encoding/json"
	"testing"
)

func TestConvertNullableSpanAttribute(t *testing.T) {
	for _, value := range []interface{}{nil, "server"} {
		data := map[string]interface{}{}
		input := `{"services":[{"service_uid":"svc","service_uname":"service"}],"tracing":[{"service_uid":"svc","deepflow_span_id":"0000000000000001","deepflow_parent_span_id":"","trace_id":"00000000000000000000000000000001","endpoint":"GET /","start_time_us":1,"end_time_us":2}]}`
		if err := json.Unmarshal([]byte(input), &data); err != nil {
			t.Fatal(err)
		}
		span := data["tracing"].([]interface{})[0].(map[string]interface{})
		span["Enum(tap_side)"] = value
		result := ConvertL7TracingRespToProto(data, "")
		got := result.Batches[0].InstrumentationLibrarySpans[0].Spans[0]
		if got.Name != "GET /" || got.StartTimeUnixNano != 1000 || got.EndTimeUnixNano != 2000 {
			t.Fatalf("unexpected span: %v", got)
		}
		found := false
		for _, attr := range got.Attributes {
			if attr.Key == "tap_side" {
				want, _ := value.(string)
				if attr.Value.GetStringValue() != want {
					t.Fatalf("tap_side = %q, want %q", attr.Value.GetStringValue(), want)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("tap_side attribute missing")
		}
	}
}
