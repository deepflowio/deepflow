package flowgenerator

import (
	"sync"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/lru"
)

type ServiceStatus struct {
	clientMap map[uint32]bool
	threshold time.Duration
	active    bool
}

type IpPortEpcKey = uint64

type ServiceManager struct {
	sync.RWMutex

	lruCache      *lru.Cache64
	getStatus     func(IpPortEpcKey, uint16) bool
	enableStatus  func(IpPortEpcKey)
	hitStatus     func(IpPortEpcKey, uint32, time.Duration)
	disableStatus func(IpPortEpcKey)
}

// inner tcp service manager allocator
// the count of service manager is equal to flow generator number
var (
	innerTcpSMA []*ServiceManager
	innerUdpSMA []*ServiceManager
)

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

var IANAPortServiceList []bool

const IANA_PORT_RANGE = 1024 + 1

func NewServiceManager(capacity int) *ServiceManager {
	serviceManager := &ServiceManager{lruCache: lru.NewCache64(capacity)}
	// if portStatsInterval is 0, then not learn any port
	if portStatsInterval > 0 {
		serviceManager.getStatus = serviceManager.getStatusLearnOn
		serviceManager.enableStatus = serviceManager.enableStatusLearnOn
		serviceManager.hitStatus = serviceManager.hitStatusLearnOn
		serviceManager.disableStatus = serviceManager.disableStatusLearnOn
	} else {
		log.Infof("port-stats-interval is %d, maybe it is unexpected", portStatsInterval)
		serviceManager.getStatus = serviceManager.getStatusLearnOff
		serviceManager.enableStatus = serviceManager.enableStatusLearnOff
		serviceManager.hitStatus = serviceManager.hitStatusLearnOff
		serviceManager.disableStatus = serviceManager.disableStatusLearnOff
	}
	return serviceManager
}

func genServiceKey(l3EpcId int32, ip IPv4Int, port uint16) IpPortEpcKey {
	return IpPortEpcKey((uint64(ip) << 32) | (uint64(port) << 16) | uint64(uint16(l3EpcId)))
}

func getTcpServiceManager(key IpPortEpcKey) *ServiceManager {
	return innerTcpSMA[key%flowGeneratorCount]
}

func getUdpServiceManager(key IpPortEpcKey) *ServiceManager {
	return innerUdpSMA[key%flowGeneratorCount]
}

func (m *ServiceManager) getStatusLearnOn(key IpPortEpcKey, port uint16) bool {
	m.RLock()
	value, ok := m.lruCache.Peek(key)
	m.RUnlock()
	if !ok {
		if port < IANA_PORT_RANGE {
			return IANAPortServiceList[port]
		}
		return false
	}
	log.Debugf("IpPortEpcKey %x, active %t", key, value.(*ServiceStatus).active)
	return value.(*ServiceStatus).active
}

func (m *ServiceManager) getStatusLearnOff(key IpPortEpcKey, port uint16) bool {
	if port < IANA_PORT_RANGE {
		return IANAPortServiceList[port]
	}
	return false
}

func (m *ServiceManager) enableStatusLearnOn(key IpPortEpcKey) {
	m.Lock()
	value, ok := m.lruCache.Get(key)
	if !ok {
		// threshold is not used for an active service port
		status := &ServiceStatus{make(map[uint32]bool), 0, false}
		status.active = true
		m.lruCache.Add(key, status)
	} else {
		status := value.(*ServiceStatus)
		status.active = true
	}
	m.Unlock()
}

func (m *ServiceManager) enableStatusLearnOff(key IpPortEpcKey) {
	return
}

func (m *ServiceManager) hitStatusLearnOn(key IpPortEpcKey, clientHash uint32, timestamp time.Duration) {
	var status *ServiceStatus
	m.Lock()
	value, ok := m.lruCache.Get(key)
	if !ok {
		status = &ServiceStatus{make(map[uint32]bool), timestamp + portStatsInterval, false}
		m.lruCache.Add(key, status)
	} else {
		status = value.(*ServiceStatus)
	}
	if status.active {
		m.Unlock()
		return
	}
	// if timestamp interval is bigger than 'learn interval',
	// then restart the learning
	if status.threshold < timestamp {
		status.threshold = timestamp + portStatsInterval
		status.active = false
		// delete will not release any memory of map
		for key := range status.clientMap {
			delete(status.clientMap, key)
		}
		log.Debugf("IpPortEpcKey %x learn failed", key)
	}
	status.clientMap[clientHash] = true
	m.Unlock()
	if len(status.clientMap) >= portStatsSrcEndCount {
		status.active = true
		log.Debugf("IpPortEpcKey %x learn as service port", key)
	}
}

func (m *ServiceManager) hitStatusLearnOff(key IpPortEpcKey, clientHash uint32, timestamp time.Duration) {
	return
}

func (m *ServiceManager) disableStatusLearnOn(key IpPortEpcKey) {
	m.Lock()
	// XXX: maybe we don't need to remove the peer
	m.lruCache.Remove(key)
	m.Unlock()
}

func (m *ServiceManager) disableStatusLearnOff(key IpPortEpcKey) {
	return
}

func init() {
	IANAPortServiceList = make([]bool, IANA_PORT_RANGE)
	for i := range IANAPortServiceList {
		IANAPortServiceList[i] = true
	}
	for _, port := range IANAPortExcludeList {
		IANAPortServiceList[port] = false
	}
}
