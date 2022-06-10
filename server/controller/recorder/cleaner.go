// 永久删除MySQL中超过7天的软删除云平台资源数据
package recorder

import (
	"time"

	"server/controller/db/mysql"
	"server/controller/recorder/constraint"
)

func delete[MT constraint.MySQLSoftDeleteModel](expiredAt time.Time) {
	err := mysql.Db.Unscoped().Where("deleted_at < ?", expiredAt).Delete(new(MT)).Error
	if err != nil {
		log.Errorf("mysql delete resource: %v failed: %s", new(MT), err)
	}
}

func CleanDeletedResources(cleanInterval, expireInterval int) {
	go func() {
		for range time.Tick(time.Duration(cleanInterval) * time.Hour) {
			log.Info("clean soft deleted resources started")
			expiredAt := time.Now().Add(time.Duration(-expireInterval) * time.Hour)
			delete[mysql.Region](expiredAt)
			delete[mysql.AZ](expiredAt)
			delete[mysql.Host](expiredAt)
			delete[mysql.VM](expiredAt)
			delete[mysql.VPC](expiredAt)
			delete[mysql.Network](expiredAt)
			delete[mysql.VRouter](expiredAt)
			delete[mysql.DHCPPort](expiredAt)
			delete[mysql.SecurityGroup](expiredAt)
			delete[mysql.NATGateway](expiredAt)
			delete[mysql.LB](expiredAt)
			delete[mysql.LBListener](expiredAt)
			delete[mysql.CEN](expiredAt)
			delete[mysql.PeerConnection](expiredAt)
			delete[mysql.RDSInstance](expiredAt)
			delete[mysql.RedisInstance](expiredAt)
			delete[mysql.PodCluster](expiredAt)
			delete[mysql.PodNode](expiredAt)
			delete[mysql.PodNamespace](expiredAt)
			delete[mysql.PodIngress](expiredAt)
			delete[mysql.PodService](expiredAt)
			delete[mysql.PodGroup](expiredAt)
			delete[mysql.PodReplicaSet](expiredAt)
			delete[mysql.Pod](expiredAt)
			log.Info("clean soft deleted resources completed")
		}
	}()
}
