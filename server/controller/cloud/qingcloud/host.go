package qingcloud

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
)

// 为了私有云可以直接继承getVMs的代码，所以公有云返回空的宿主机列表
func (q *QingCloud) getHosts() ([]model.Host, error) {
	var retHosts []model.Host
	q.HostNameToIP = make(map[string]string)
	return retHosts, nil
}
