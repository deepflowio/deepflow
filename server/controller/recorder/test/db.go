package test

import (
	"fmt"
	"os"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"server/controller/db/mysql"
	"server/controller/recorder/constraint"
)

func GetDB(dbFile string) *gorm.DB {
	db, err := gorm.Open(
		sqlite.Open(dbFile),
		&gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}},
	)
	if err != nil {
		fmt.Printf("create sqlite database failed: %s\n", err.Error())
		os.Exit(1)
	}

	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(50)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	return db
}

func GetModels() []interface{} {
	return []interface{}{
		&mysql.Domain{}, &mysql.Region{}, &mysql.AZ{}, &mysql.SubDomain{}, &mysql.Host{}, &mysql.VM{},
		&mysql.VPC{}, &mysql.Network{}, &mysql.Subnet{}, &mysql.VRouter{}, &mysql.RoutingTable{},
		&mysql.DHCPPort{}, &mysql.VInterface{}, &mysql.WANIP{}, &mysql.LANIP{}, &mysql.FloatingIP{},
		&mysql.SecurityGroup{}, &mysql.SecurityGroupRule{}, &mysql.VMSecurityGroup{}, &mysql.LB{},
		&mysql.LBListener{}, &mysql.LBTargetServer{}, &mysql.NATGateway{}, &mysql.NATRule{},
		&mysql.NATVMConnection{}, &mysql.LBVMConnection{}, &mysql.CEN{}, &mysql.PeerConnection{},
		&mysql.RDSInstance{}, &mysql.RedisInstance{},
		&mysql.PodCluster{}, &mysql.PodNode{}, &mysql.PodNamespace{}, &mysql.VMPodNodeConnection{},
		&mysql.PodIngress{}, &mysql.PodIngressRule{}, &mysql.PodIngressRuleBackend{},
		&mysql.PodService{}, &mysql.PodServicePort{}, &mysql.PodGroup{}, &mysql.PodGroupPort{},
		&mysql.PodReplicaSet{}, &mysql.Pod{},
	}
}

func ClearDBData[MT constraint.MySQLModel](db *gorm.DB) {
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(new(MT))
}
