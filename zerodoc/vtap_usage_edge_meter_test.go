package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/codec"

	"testing"
)

func TestVTAPEdgeMeterEnDecode(t *testing.T) {
	m := VTAPUsageEdgeMeter{}
	fillMetrics(1, (*Metrics)(&m))
	encoder := codec.SimpleEncoder{}
	m.Encode(&encoder)

	decoder := codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	decoded := VTAPUsageEdgeMeter{}
	decoded.Decode(&decoder)

	if m != decoded {
		t.Errorf("expect: %v, result %v", m, decoded)
	}
}

func TestVTAPEdgeMeterMerge(t *testing.T) {
	a := VTAPUsageMeter{}
	fillMetrics(1, (*Metrics)(&a))

	b := a
	fillMetrics(2, (*Metrics)(&b))
	b2 := b

	c := b
	fillMetrics(3, (*Metrics)(&c))

	b.ConcurrentMerge(&a)

	if b != c {
		t.Errorf("expect: %v, result %v", b, c)
	}

	b2.SequentialMerge(&a)

	if b2 != c {
		t.Errorf("expect: %v, result %v", b2, c)
	}
}
