package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type Metrics struct {
	TxBytes   uint64
	RxBytes   uint64
	TxPackets uint64
	RxPackets uint64
}

type MetricsField uint32

const (
	// L2
	METRICS_BROADCAST MetricsField = 1 << iota
	METRICS_MULTICAST
	METRICS_UNICAST

	// L3
	METRICS_TCP_IN_EPC
	METRICS_TCP_OUT_EPC
	METRICS_UDP_IN_EPC
	METRICS_UDP_OUT_EPC
	METRICS_OTHERS_IN_EPC
	METRICS_OTHERS_OUT_EPC
	// L3, for VTAPUsageEdgeMeter
	METRICS_TCP
	METRICS_UDP
	METRICS_OTHERS

	// TCP
	METRICS_TCP_FLAG_SYN     // SYN
	METRICS_TCP_FLAG_SYN_ACK // SYN+ACK
	METRICS_TCP_FLAG_ACK     // ACK
	METRICS_TCP_FLAG_PSH_ACK // PSH+ACK
	METRICS_TCP_FLAG_FIN_ACK // FIN+ACK
	METRICS_TCP_FLAG_RST_ACK // RST+ACK
	METRICS_TCP_FLAG_OTHERS  // others
)

type VTAPUsageMeter struct {
	Fields MetricsField

	// L2
	Broadcast Metrics
	Multicast Metrics
	Unicast   Metrics

	// L3
	TCPInEPC     Metrics
	TCPOutEPC    Metrics
	UDPInEPC     Metrics
	UDPOutEPC    Metrics
	OthersInEPC  Metrics
	OthersOutEPC Metrics

	// TCP
	TCPFlagSYN    Metrics
	TCPFlagSYNACK Metrics
	TCPFlagACK    Metrics
	TCPFlagPSHACK Metrics
	TCPFlagFINACK Metrics
	TCPFlagRSTACK Metrics
	TCPFlagOthers Metrics
}

func (m *Metrics) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU64(m.TxBytes)
	encoder.WriteU64(m.RxBytes)
	encoder.WriteU64(m.TxPackets)
	encoder.WriteU64(m.RxPackets)
}

func (m *Metrics) Decode(decoder *codec.SimpleDecoder) {
	m.TxBytes = decoder.ReadU64()
	m.RxBytes = decoder.ReadU64()
	m.TxPackets = decoder.ReadU64()
	m.RxPackets = decoder.ReadU64()
}

func (m *Metrics) SortKey() uint64 {
	return uint64(m.TxBytes) + uint64(m.RxBytes)
}

func (m *Metrics) ToKVString() string {
	panic("not supported!")
}

func (m *Metrics) MarshalTo(b []byte) int {
	panic("not supported!")
}

func (m *Metrics) Clone() app.Meter {
	panic("not supported!")
}

func (m *Metrics) Release() {
	panic("not supported!")
}

func (m *Metrics) Merge(other *Metrics) {
	m.TxBytes += other.TxBytes
	m.RxBytes += other.RxBytes
	m.TxPackets += other.TxPackets
	m.RxPackets += other.RxPackets
}

func (m *Metrics) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*Metrics); ok {
		m.Merge(other)
	}
}

func (m *Metrics) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}

func (m *VTAPUsageMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteU32(uint32(m.Fields))

	if m.Fields&METRICS_BROADCAST != 0 {
		m.Broadcast.Encode(encoder)
	}
	if m.Fields&METRICS_MULTICAST != 0 {
		m.Multicast.Encode(encoder)
	}
	if m.Fields&METRICS_UNICAST != 0 {
		m.Unicast.Encode(encoder)
	}

	if m.Fields&METRICS_TCP_IN_EPC != 0 {
		m.TCPInEPC.Encode(encoder)
	}
	if m.Fields&METRICS_TCP_OUT_EPC != 0 {
		m.TCPOutEPC.Encode(encoder)
	}
	if m.Fields&METRICS_UDP_IN_EPC != 0 {
		m.UDPInEPC.Encode(encoder)
	}
	if m.Fields&METRICS_UDP_OUT_EPC != 0 {
		m.UDPOutEPC.Encode(encoder)
	}
	if m.Fields&METRICS_OTHERS_IN_EPC != 0 {
		m.OthersInEPC.Encode(encoder)
	}
	if m.Fields&METRICS_OTHERS_OUT_EPC != 0 {
		m.OthersOutEPC.Encode(encoder)
	}

	if m.Fields&METRICS_TCP_FLAG_SYN != 0 {
		m.TCPFlagSYN.Encode(encoder)
	}
	if m.Fields&METRICS_TCP_FLAG_SYN_ACK != 0 {
		m.TCPFlagSYNACK.Encode(encoder)
	}
	if m.Fields&METRICS_TCP_FLAG_ACK != 0 {
		m.TCPFlagACK.Encode(encoder)
	}
	if m.Fields&METRICS_TCP_FLAG_PSH_ACK != 0 {
		m.TCPFlagPSHACK.Encode(encoder)
	}
	if m.Fields&METRICS_TCP_FLAG_FIN_ACK != 0 {
		m.TCPFlagFINACK.Encode(encoder)
	}
	if m.Fields&METRICS_TCP_FLAG_RST_ACK != 0 {
		m.TCPFlagRSTACK.Encode(encoder)
	}
	if m.Fields&METRICS_TCP_FLAG_OTHERS != 0 {
		m.TCPFlagOthers.Encode(encoder)
	}
}

func (m *VTAPUsageMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Fields = MetricsField(decoder.ReadU32())

	if m.Fields&METRICS_BROADCAST != 0 {
		m.Broadcast.Decode(decoder)
	}
	if m.Fields&METRICS_MULTICAST != 0 {
		m.Multicast.Decode(decoder)
	}
	if m.Fields&METRICS_UNICAST != 0 {
		m.Unicast.Decode(decoder)
	}

	if m.Fields&METRICS_TCP_IN_EPC != 0 {
		m.TCPInEPC.Decode(decoder)
	}
	if m.Fields&METRICS_TCP_OUT_EPC != 0 {
		m.TCPOutEPC.Decode(decoder)
	}
	if m.Fields&METRICS_UDP_IN_EPC != 0 {
		m.UDPInEPC.Decode(decoder)
	}
	if m.Fields&METRICS_UDP_OUT_EPC != 0 {
		m.UDPOutEPC.Decode(decoder)
	}
	if m.Fields&METRICS_OTHERS_IN_EPC != 0 {
		m.OthersInEPC.Decode(decoder)
	}
	if m.Fields&METRICS_OTHERS_OUT_EPC != 0 {
		m.OthersOutEPC.Decode(decoder)
	}

	if m.Fields&METRICS_TCP_FLAG_SYN != 0 {
		m.TCPFlagSYN.Decode(decoder)
	}
	if m.Fields&METRICS_TCP_FLAG_SYN_ACK != 0 {
		m.TCPFlagSYNACK.Decode(decoder)
	}
	if m.Fields&METRICS_TCP_FLAG_ACK != 0 {
		m.TCPFlagACK.Decode(decoder)
	}
	if m.Fields&METRICS_TCP_FLAG_PSH_ACK != 0 {
		m.TCPFlagPSHACK.Decode(decoder)
	}
	if m.Fields&METRICS_TCP_FLAG_FIN_ACK != 0 {
		m.TCPFlagFINACK.Decode(decoder)
	}
	if m.Fields&METRICS_TCP_FLAG_RST_ACK != 0 {
		m.TCPFlagRSTACK.Decode(decoder)
	}
	if m.Fields&METRICS_TCP_FLAG_OTHERS != 0 {
		m.TCPFlagOthers.Decode(decoder)
	}
}

func (m *VTAPUsageMeter) SortKey() uint64 {
	panic("not supported!")
}

func (m *VTAPUsageMeter) ToKVString() string {
	panic("not supported!")
}

func (m *VTAPUsageMeter) MarshalTo(b []byte) int {
	panic("not supported!")
}

func (m *VTAPUsageMeter) ConcurrentMerge(other app.Meter) {
	if other, ok := other.(*VTAPUsageMeter); ok {
		m.Fields |= other.Fields

		if m.Fields&METRICS_BROADCAST != 0 {
			m.Broadcast.Merge(&other.Broadcast)
		}
		if m.Fields&METRICS_MULTICAST != 0 {
			m.Multicast.Merge(&other.Multicast)
		}
		if m.Fields&METRICS_UNICAST != 0 {
			m.Unicast.Merge(&other.Unicast)
		}

		if m.Fields&METRICS_TCP_IN_EPC != 0 {
			m.TCPInEPC.Merge(&other.TCPInEPC)
		}
		if m.Fields&METRICS_TCP_OUT_EPC != 0 {
			m.TCPOutEPC.Merge(&other.TCPOutEPC)
		}
		if m.Fields&METRICS_UDP_IN_EPC != 0 {
			m.UDPInEPC.Merge(&other.UDPInEPC)
		}
		if m.Fields&METRICS_UDP_OUT_EPC != 0 {
			m.UDPOutEPC.Merge(&other.UDPOutEPC)
		}
		if m.Fields&METRICS_OTHERS_IN_EPC != 0 {
			m.OthersInEPC.Merge(&other.OthersInEPC)
		}
		if m.Fields&METRICS_OTHERS_OUT_EPC != 0 {
			m.OthersOutEPC.Merge(&other.OthersOutEPC)
		}

		if m.Fields&METRICS_TCP_FLAG_SYN != 0 {
			m.TCPFlagSYN.Merge(&other.TCPFlagSYN)
		}
		if m.Fields&METRICS_TCP_FLAG_SYN_ACK != 0 {
			m.TCPFlagSYNACK.Merge(&other.TCPFlagSYNACK)
		}
		if m.Fields&METRICS_TCP_FLAG_ACK != 0 {
			m.TCPFlagACK.Merge(&other.TCPFlagACK)
		}
		if m.Fields&METRICS_TCP_FLAG_PSH_ACK != 0 {
			m.TCPFlagPSHACK.Merge(&other.TCPFlagPSHACK)
		}
		if m.Fields&METRICS_TCP_FLAG_FIN_ACK != 0 {
			m.TCPFlagFINACK.Merge(&other.TCPFlagFINACK)
		}
		if m.Fields&METRICS_TCP_FLAG_RST_ACK != 0 {
			m.TCPFlagRSTACK.Merge(&other.TCPFlagRSTACK)
		}
		if m.Fields&METRICS_TCP_FLAG_OTHERS != 0 {
			m.TCPFlagOthers.Merge(&other.TCPFlagOthers)
		}
	}
}

func (m *VTAPUsageMeter) SequentialMerge(other app.Meter) {
	m.ConcurrentMerge(other)
}
