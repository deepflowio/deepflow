package monitor

import (
	"fmt"
	"net/http"
	"time"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("monitor")

type dfHostCheck struct {
	lastTimeUnix int64
}

func newDFHostCheck() *dfHostCheck {
	return &dfHostCheck{lastTimeUnix: time.Now().Unix()}
}

func (h *dfHostCheck) duration() int64 {
	return (time.Now().Unix() - h.lastTimeUnix)
}

// TODO: 后续修改为通过RPC调用
func isActive(urlPrefix string, ip string, port int) bool {
	url := fmt.Sprintf(urlPrefix, ip, port)
	response, err := http.Get(url)
	if err != nil {
		log.Warningf("curl (%s) failed, (%v)", url, err)
	} else if response.StatusCode != http.StatusOK {
		log.Warning("curl (%s) failed, (%d)", url, response.StatusCode)
	}
	return err == nil && response.StatusCode == http.StatusOK
}
