package common

const (
	SUCCESS = "SUCCESS"
)

const (
	DEFAULT_ENCRYPTION_PASSWORD = "******"

	TENCENT_EN    = "tencent"
	ALIYUN_EN     = "aliyun"
	KUBERNETES_EN = "kubernetes"
	QINGCLOUD_EN  = "qingcloud"
	GENESIS_EN    = "genesis"
	BAIDU_BCE_EN  = "baidu_bce"
)

const (
	VTAP_STATE_NOT_CONNECTED = iota
	VTAP_STATE_NORMAL
	VTAP_STATE_DISABLE
	VTAP_STATE_PENDING
)

const (
	VTAP_STATE_NOT_CONNECTED_STR = "LOST"
	VTAP_STATE_NORMAL_STR        = "RUNNING"
	VTAP_STATE_DISABLE_STR       = "DISABLE"
	VTAP_STATE_PENDING_STR       = "PENDING"
)
