package policy

import (
	"reflect"
	"testing"

	. "gitlab.yunshan.net/yunshan/droplet-libs/datatype"
)

func TestPortSegmentSimple(t *testing.T) {
	ports := newPortSegments(NewPortRange(5, 6))
	if !reflect.DeepEqual(ports, []portSegment{portSegment{5, 65535}, portSegment{6, 65535}}) {
		t.Errorf("Error portsegment range(5, 6) return %v\n", ports)
	}
	ports = newPortSegments(NewPortRange(4, 4))
	if !reflect.DeepEqual(ports, []portSegment{portSegment{4, 65535}}) {
		t.Errorf("Error portsegment range(4, 4) return %v\n", ports)
	}
	ports = newPortSegments(NewPortRange(4, 5))
	if !reflect.DeepEqual(ports, []portSegment{portSegment{4, 65534}}) {
		t.Errorf("Error portsegment range(4, 5) return %v\n", ports)
	}
	ports = newPortSegments(NewPortRange(4, 6))
	if !reflect.DeepEqual(ports, []portSegment{portSegment{4, 65534}, portSegment{6, 65535}}) {
		t.Errorf("Error portsegment range(4, 6) return %v\n", ports)
	}

	expect := []portSegment{portSegment{4, 65532}, portSegment{8, 65528}, portSegment{16, 65520}, portSegment{32, 65504}, portSegment{64, 65504}, portSegment{96, 65532}, portSegment{100, 65535}}
	ports = newPortSegments(NewPortRange(4, 100))
	if !reflect.DeepEqual(ports, expect) {
		t.Errorf("Error portsegment range(4, 100) return %v\n", ports)
	}

	ports = newPortSegments(NewPortRange(0, 0))
	if !reflect.DeepEqual(ports, []portSegment{portSegment{0, 65535}}) {
		t.Errorf("Error portsegment range(0, 0) return %v\n", ports)
	}
	ports = newPortSegments(NewPortRange(0, 3))
	if !reflect.DeepEqual(ports, []portSegment{portSegment{0, 65532}}) {
		t.Errorf("Error portsegment range(0, 3) return %v\n", ports)
	}
	ports = newPortSegments(NewPortRange(65533, 65535))
	if !reflect.DeepEqual(ports, []portSegment{portSegment{65533, 65535}, portSegment{65534, 65534}}) {
		t.Errorf("Error portsegment range(65533, 65535) return %v\n", ports)
	}
	ports = newPortSegments(NewPortRange(65535, 65535))
	if !reflect.DeepEqual(ports, []portSegment{portSegment{65535, 65535}}) {
		t.Errorf("Error portsegment range(65535, 65535) return %v\n", ports)
	}
}
