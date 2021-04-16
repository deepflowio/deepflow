package dbwriter

import (
	"encoding/json"
	"testing"

	"gitlab.x.lan/yunshan/droplet/stream/common"
)

func TestJsonUnmarshall(t *testing.T) {
	var j interface{}
	l4 := buildJsonBody(common.L4_FLOW_LOG, 0, false)
	if err := json.Unmarshal([]byte(l4), &j); err != nil {
		t.Error("l4 json unmarshall failed", err)
	}

	l7HTTP := buildJsonBody(common.L4_FLOW_LOG, 1, true)
	if err := json.Unmarshal([]byte(l7HTTP), &j); err != nil {
		t.Error("l7 HTTP  json unmarshall failed", err)
	}

	l7DNS := buildJsonBody(common.L4_FLOW_LOG, 0, false)
	if err := json.Unmarshal([]byte(l7DNS), &j); err != nil {
		t.Error("l7 DNS json unmarshall failed", err)
	}
}
