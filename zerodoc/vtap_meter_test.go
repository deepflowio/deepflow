package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/codec"

	"testing"
)

func fillMetrics(hint uint64, m *Metrics) {
	m.TxBytes = hint * 97
	m.RxBytes = hint * 89
	m.TxPackets = hint * 3
	m.RxPackets = hint * 2
}

func TestVTAPMeterEnDecode(t *testing.T) {
	m := VTAPUsageMeter{}
	fillMetrics(1, (*Metrics)(&m))
	encoder := codec.SimpleEncoder{}
	m.Encode(&encoder)

	decoder := codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	decoded := VTAPUsageMeter{}
	decoded.Decode(&decoder)

	if m != decoded {
		t.Errorf("expect: %v, result %v", m, decoded)
	}
}

func TestVTAPMeterMerge(t *testing.T) {
	a := VTAPUsageMeter{}
	fillMetrics(1, (*Metrics)(&a))

	b := a
	fillMetrics(2, (*Metrics)(&b))
	b2 := b

	c := b
	fillMetrics(3, (*Metrics)(&c))

	b.ConcurrentMerge(&a)

	if b != c {
		t.Errorf("expect: %v, result %v", c, b)
	}

	b2.SequentialMerge(&a)

	if b2 != c {
		t.Errorf("expect: %v, result %v", c, b2)
	}
}
