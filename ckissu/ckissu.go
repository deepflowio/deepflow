package ckissu

import (
	"fmt"
	"strings"

	logging "github.com/op/go-logging"

	"database/sql"

	"gitlab.yunshan.net/yunshan/droplet/common"
)

var log = logging.MustGetLogger("issu")

type Issu struct {
	columnRenames                          []*ColumnRename
	primaryConnection, SecondaryConnection *sql.DB
	primaryAddr, secondaryAddr             string
	username, password                     string
	exit                                   bool
}

type DbTable struct {
}

type ColumnRename struct {
	Db            string
	Table         string
	OldColumnName string
	NewColumnName string
}

var ColumnRename572 = []*ColumnRename{
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l4_flow_log",
		OldColumnName: "retan_tx",
		NewColumnName: "retran_tx",
	},
	&ColumnRename{
		Db:            "flow_log",
		Table:         "l4_flow_log_local",
		OldColumnName: "retan_tx",
		NewColumnName: "retran_tx",
	},
}

func NewCKIssu(primaryAddr, secondaryAddr, username, password string) (*Issu, error) {
	i := &Issu{
		primaryAddr:   primaryAddr,
		secondaryAddr: secondaryAddr,
		username:      username,
		password:      password,
		columnRenames: ColumnRename572,
	}
	var err error
	i.primaryConnection, err = common.NewCKConnection(primaryAddr, username, password)
	if err != nil {
		return nil, err
	}

	if secondaryAddr != "" {
		i.SecondaryConnection, err = common.NewCKConnection(secondaryAddr, username, password)
		if err != nil {
			return nil, err
		}
	}

	return i, nil
}

func (i *Issu) renameColumn(connect *sql.DB, cr *ColumnRename) error {
	// ALTER TABLE flow_log.l4_flow_log  RENAME COLUMN retan_tx TO retran_tx
	sql := fmt.Sprintf("ALTER TABLE %s.%s RENAME COLUMN %s to %s",
		cr.Db, cr.Table, cr.OldColumnName, cr.NewColumnName)
	_, err := connect.Exec(sql)
	if err != nil {
		// 如果已经修改过，就会报错不存在column，需要跳过该错误
		// Code: 10. DB::Exception: Received from localhost:9000. DB::Exception: Wrong column name. Cannot find column `retan_tx` to rename.
		if strings.Contains(err.Error(), "Cannot find column") {
			log.Infof("db: %s, table: %s error: %s", cr.Db, cr.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}
	return nil
}

func (i *Issu) getTableVersion(connect *sql.DB, db, table string) (string, error) {
	sql := fmt.Sprintf("SELECT comment FROM system.columns WHERE database='%s' AND table='%s' AND name='time'",
		db, table)
	rows, err := connect.Query(sql)
	if err != nil {
		return "", err
	}
	var version string
	for rows.Next() {
		err := rows.Scan(&version)
		if err != nil {
			return "", err
		}
	}
	return version, nil
}

func (i *Issu) setTableVersion(connect *sql.DB, db, table string) error {
	sql := fmt.Sprintf("ALTER TABLE %s.%s COMMENT COLUMN time '%s'",
		db, table, common.CK_VERSION)
	_, err := connect.Exec(sql)
	return err
}

func (i *Issu) renameColumns(connect *sql.DB) ([]*ColumnRename, error) {
	dones := []*ColumnRename{}
	for _, renameColumn := range i.columnRenames {
		version, err := i.getTableVersion(connect, renameColumn.Db, renameColumn.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			continue
		}
		if err := i.renameColumn(connect, renameColumn); err != nil {
			return dones, err
		}
		dones = append(dones, renameColumn)
	}

	return dones, nil
}

func (i *Issu) Start() error {
	for _, connect := range []*sql.DB{i.primaryConnection, i.SecondaryConnection} {
		if connect == nil {
			continue
		}
		dones, err := i.renameColumns(connect)
		for _, cr := range dones {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *Issu) Close() {
	for _, connect := range []*sql.DB{i.primaryConnection, i.SecondaryConnection} {
		if connect == nil {
			continue
		}
		connect.Close()
	}
}
