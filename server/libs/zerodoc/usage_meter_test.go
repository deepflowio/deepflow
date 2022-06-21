package zerodoc

import (
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
	"gitlab.yunshan.net/yunshan/droplet-libs/zerodoc/pb"

	"testing"
)

func fillMetrics(hint uint64, m *UsageMeter) {
	m.PacketTx = hint * 3
	m.PacketRx = hint * 2
	m.ByteTx = hint * 97
	m.ByteRx = hint * 89
	m.L3ByteTx = hint * 96
	m.L3ByteRx = hint * 88
	m.L4ByteTx = hint * 95
	m.L4ByteRx = hint * 87
}

func TestVTAPMeterEnDecode(t *testing.T) {
	m := UsageMeter{}
	pbEncode := &pb.UsageMeter{}
	fillMetrics(1, &m)
	encoder := codec.SimpleEncoder{}
	m.WriteToPB(pbEncode)
	encoder.WritePB(pbEncode)

	decoder := codec.SimpleDecoder{}
	decoder.Init(encoder.Bytes())
	pbDecode := &pb.UsageMeter{}
	decoder.ReadPB(pbDecode)
	decoded := UsageMeter{}
	decoded.ReadFromPB(pbDecode)

	if m != decoded {
		t.Errorf("expect: %v, result %v", m, decoded)
	}
}

func TestVTAPMeterMerge(t *testing.T) {
	a := UsageMeter{}
	fillMetrics(1, &a)

	b := a
	fillMetrics(2, &b)
	b2 := b

	c := b
	fillMetrics(3, &c)

	b.ConcurrentMerge(&a)

	if b != c {
		t.Errorf("expect: %v, result %v", c, b)
	}

	b2.SequentialMerge(&a)

	if b2 != c {
		t.Errorf("expect: %v, result %v", c, b2)
	}
}
