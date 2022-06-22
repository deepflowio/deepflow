package tagrecorder

type IDKey struct {
	ID int
}

type DeviceKey struct {
	DeviceID   int
	DeviceType int
}

type IPResourceKey struct {
	IP       string
	SubnetID int
}

type PortIDKey struct {
	ID       int
	Protocol int
	Port     int
}

type PortIPKey struct {
	IP       string
	SubnetID int
	Protocol int
	Port     int
}

type PortDeviceKey struct {
	DeviceID   int
	DeviceType int
	Protocol   int
	Port       int
}

type VtapPortKey struct {
	VtapID  int
	TapPort int64
}

type IPRelationKey struct {
	VPCID int
	IP    string
}

type K8sLabelKey struct {
	PodID int
	Key   string
}

type TapTypeKey struct {
	Value int
}
