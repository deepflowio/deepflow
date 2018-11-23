package flowgenerator

import (
	"sync"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

type ServiceStatus bool

type IpPortEpcKey uint64

type ServiceMap map[IpPortEpcKey]ServiceStatus

type ServiceManager struct {
	sync.RWMutex

	lruCache *Cache
}

var IANAPortExcludeList = []uint16{
	4, 6, 8, 10, 12, 14, 15, 16, 26, 28,
	30, 32, 34, 36, 40, 60, 81, 100, 114, 258,
	272, 273, 274, 275, 276, 277, 278, 279, 285, 288,
	289, 290, 291, 292, 293, 294, 295, 296, 297, 298,
	299, 300, 301, 302, 303, 304, 305, 306, 307, 325,
	326, 327, 328, 329, 330, 331, 332, 334, 335, 336,
	337, 338, 339, 340, 341, 342, 343, 703, 708, 717,
	718, 719, 720, 721, 722, 723, 724, 725, 726, 727,
	728, 732, 733, 734, 735, 736, 737, 738, 739, 740,
	745, 746, 755, 756, 757, 778, 779, 781, 782, 783,
	784, 785, 788, 789, 790, 791, 792, 793, 794, 795,
	796, 797, 798, 799, 803, 804, 805, 806, 807, 808,
	809, 811, 812, 813, 814, 815, 816, 817, 818, 819,
	820, 821, 822, 823, 824, 825, 826, 827, 834, 835,
	836, 837, 838, 839, 840, 841, 842, 843, 844, 845,
	846, 849, 850, 851, 852, 855, 856, 857, 858, 859,
	863, 864, 865, 866, 867, 868, 869, 870, 871, 872,
	874, 875, 876, 877, 878, 879, 880, 881, 882, 883,
	884, 885, 889, 890, 891, 892, 893, 894, 895, 896,
	897, 898, 899, 904, 905, 906, 907, 908, 909, 914,
	915, 916, 917, 918, 919, 920, 921, 922, 923, 924,
	925, 926, 927, 928, 929, 930, 931, 932, 933, 934,
	935, 936, 937, 938, 939, 940, 941, 942, 943, 944,
	945, 946, 947, 948, 949, 950, 951, 952, 954, 955,
	956, 957, 958, 959, 960, 961, 962, 963, 964, 965,
	966, 967, 968, 969, 970, 971, 972, 973, 974, 975,
	976, 977, 978, 979, 980, 981, 982, 983, 984, 985,
	986, 987, 988, 1002, 1003, 1004, 1005, 1006, 1007,
}

var IANAPortServiceList []ServiceStatus

const IANA_PORT_RANGE = 1024 + 1

func NewServiceManager(capacity int) *ServiceManager {
	return &ServiceManager{lruCache: NewCache(capacity)}
}

func (m *ServiceManager) getStatus(l3EpcId int32, ip IPv4Int, port uint16) ServiceStatus {
	key := IpPortEpcKey((uint64(ip) << 32) | (uint64(port) << 16) | uint64(l3EpcId))
	m.RLock()
	status, ok := m.lruCache.Check(key)
	m.RUnlock()
	if !ok {
		if port < IANA_PORT_RANGE {
			return IANAPortServiceList[port]
		}
		return false
	}
	return status.(ServiceStatus)
}

func (m *ServiceManager) enableStatus(l3EpcId int32, ip IPv4Int, port uint16) {
	key := IpPortEpcKey((uint64(ip) << 32) | (uint64(port) << 16) | uint64(l3EpcId))
	m.Lock()
	m.lruCache.Add(key, ServiceStatus(true))
	m.Unlock()
}

func (m *ServiceManager) disableStatus(l3EpcId int32, ip IPv4Int, port uint16) {
	key := IpPortEpcKey((uint64(ip) << 32) | (uint64(port) << 16) | uint64(l3EpcId))
	m.Lock()
	// XXX: maybe we don't need to remove the peer
	m.lruCache.Remove(key)
	m.Unlock()
}

func init() {
	IANAPortServiceList = make([]ServiceStatus, IANA_PORT_RANGE)
	for i := range IANAPortServiceList {
		IANAPortServiceList[i] = true
	}
	for _, port := range IANAPortExcludeList {
		IANAPortServiceList[port] = false
	}
}
