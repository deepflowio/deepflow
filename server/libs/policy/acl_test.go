package policy

import (
	"reflect"
	"testing"

	. "gitlab.yunshan.net/yunshan/droplet-libs/datatype"
)

func TestAclSimple(t *testing.T) {
	acl := Acl{}
	in := []uint16{1, 3, 4, 5, 10, 11, 12}
	out := acl.getPortRange(in)
	if !reflect.DeepEqual(out, []PortRange{NewPortRange(1, 1), NewPortRange(3, 5), NewPortRange(10, 12)}) {
		t.Errorf("TestAclSimple in(%v) out(%v)\n", in, out)
	}
}
