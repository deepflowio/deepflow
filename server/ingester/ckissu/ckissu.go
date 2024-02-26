/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ckissu

import (
	"fmt"
	"regexp"
	"strings"

	logging "github.com/op/go-logging"

	"database/sql"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/datasource"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics"
)

var log = logging.MustGetLogger("issu")

const (
	INTERVAL_HOUR = 60
	INTERVAL_DAY  = 1440
	DEFAULT_TTL   = 168
)

type Issu struct {
	cfg                *config.Config
	tableRenames       []*TableRename
	columnRenames      []*ColumnRename
	columnMods         []*ColumnMod
	columnAdds         []*ColumnAdd
	indexAdds          []*IndexAdd
	columnDrops        []*ColumnDrop
	modTTLs            []*TableModTTL
	datasourceInfo     map[string]*DatasourceInfo
	Connections        common.DBs
	Addrs              []string
	username, password string
	exit               bool
}

type TableRename struct {
	OldDb     string
	OldTables []string
	NewDb     string
	NewTables []string
}

type TableModTTL struct {
	Db     string
	Table  string
	NewTTL int
}

type ColumnRenames struct {
	Db              string
	Tables          []string
	OldColumnNames  []string
	CheckColumnType bool
	OldColumnTypes  []ckdb.ColumnType
	NewColumnNames  []string
	DropIndex       bool
	DropMvTable     bool
}

type ColumnRename struct {
	Db              string
	Table           string
	OldColumnName   string
	CheckColumnType bool
	OldColumnType   ckdb.ColumnType
	NewColumnName   string
	DropIndex       bool
	DropMvTable     bool
}

type ColumnMod struct {
	Db            string
	Table         string
	ColumnName    string
	NewColumnType ckdb.ColumnType
	DropIndex     bool
}

type ColumnAdd struct {
	Db           string
	Table        string
	ColumnName   string
	ColumnType   ckdb.ColumnType
	DefaultValue string
}

type ColumnAdds struct {
	Dbs          []string
	Tables       []string
	ColumnNames  []string
	ColumnType   ckdb.ColumnType
	DefaultValue string
}

type ColumnDrop struct {
	Db         string
	Table      string
	ColumnName string
}

type ColumnDrops struct {
	Dbs         []string
	Tables      []string
	ColumnNames []string
}

type IndexAdds struct {
	Dbs         []string
	Tables      []string
	ColumnNames []string
	IndexType   ckdb.IndexType
}

type IndexAdd struct {
	Db         string
	Table      string
	ColumnName string
	IndexType  ckdb.IndexType
}

type ColumnDatasourceAdds struct {
	ColumnNames                []string
	OldColumnNames             []string
	ColumnTypes                []ckdb.ColumnType
	OnlyMapTable, OnlyAppTable bool
}

type ColumnDatasourceAdd struct {
	ColumnName                 string
	OldColumnName              string
	ColumnType                 ckdb.ColumnType
	OnlyMapTable, OnlyAppTable bool
}

func getTables(connect *sql.DB, db, tableName string) ([]string, error) {
	sql := fmt.Sprintf("SHOW TABLES IN %s", db)
	log.Infof("exec sql: %s", sql)
	rows, err := connect.Query(sql)
	if err != nil {
		return nil, err
	}
	tables := []string{}
	var table string
	for rows.Next() {
		err := rows.Scan(&table)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(table, tableName) ||
			len(tableName) == 0 {
			tables = append(tables, table)
		}
	}
	return tables, nil
}

func getMvTables(connect *sql.DB, db, tableName string) ([]string, error) {
	tables, err := getTables(connect, db, tableName)
	if err != nil {
		return nil, err
	}
	mvTables := []string{}
	for _, table := range tables {
		if strings.HasSuffix(table, "_mv") {
			mvTables = append(mvTables, table)
		}
	}
	return mvTables, nil
}

type DatasourceInfo struct {
	db         string
	name       string
	baseTable  string
	summable   string
	unsummable string
	interval   ckdb.TimeFuncType
}

func (i *Issu) getDatasourceInfo(connect *sql.DB, db, mvTableName string) (*DatasourceInfo, error) {
	if info, ok := i.datasourceInfo[db+mvTableName]; ok {
		return info, nil
	}
	sql := fmt.Sprintf("SHOW CREATE TABLE %s.`%s`", db, mvTableName)
	rows, err := connect.Query(sql)
	if err != nil {
		return nil, err
	}
	var createSql string
	for rows.Next() {
		err := rows.Scan(&createSql)
		if err != nil {
			return nil, err
		}
	}
	log.Infof("getDatasourceInfo sql: %s createSql: %s ", sql, createSql)
	var summable, unsummable, interval, baseTable string
	var matchs [4]string
	// 匹配 `packet_tx__agg` AggregateFunction(sum, UInt64), 中的 'sum' 为可累加聚合的方法
	summableReg := regexp.MustCompile("`packet_tx__agg` AggregateFunction.([a-z]+)")
	// 匹配 `rtt_sum__agg` AggregateFunction(avg, Float64), 中的 'avg' 为非可累加聚合的方法
	unsummableReg := regexp.MustCompile("`rtt_sum__agg` AggregateFunction.([a-zA-Z]+)")
	if strings.HasPrefix(mvTableName, "vtap_app") || strings.HasPrefix(mvTableName, "application") {
		summableReg = regexp.MustCompile("`request__agg` AggregateFunction.([a-z]+)")
		unsummableReg = regexp.MustCompile("`rrt_sum__agg` AggregateFunction.([a-zA-Z]+)")
	}
	// 匹配 toStartOfHour(time) AS time, 中的 'Hour' 为聚合时长
	intervalReg := regexp.MustCompile("toStartOf([a-zA-Z]+)")
	// 匹配 FROM vtap_flow.`1m_local` 中的'1m' 为原始数据源
	baseTableReg := regexp.MustCompile("FROM .*.`.*\\.(.*)_local`")

	for i, reg := range []*regexp.Regexp{summableReg, unsummableReg, intervalReg, baseTableReg} {
		submatchs := reg.FindStringSubmatch(createSql)
		if len(submatchs) > 1 {
			matchs[i] = submatchs[1]
		} else {
			return nil, fmt.Errorf("parase %d failed", i)
		}
	}
	summable, unsummable, interval, baseTable = matchs[0], matchs[1], matchs[2], matchs[3]
	if unsummable == "argMax" {
		unsummable = "max"
	} else if unsummable == "argMin" {
		unsummable = "min"
	}
	log.Info("get summable, unsummable, interval, baseTable:", summable, unsummable, interval, baseTable)

	intervalTime := ckdb.TimeFuncHour
	if interval == "Day" {
		intervalTime = ckdb.TimeFuncDay
	} else if interval == "Hour" {
		intervalTime = ckdb.TimeFuncHour
	} else {
		return nil, fmt.Errorf("invalid interval %s", interval)
	}

	return &DatasourceInfo{
		db:         db,
		baseTable:  baseTable,
		name:       mvTableName[:len(mvTableName)-len("_mv")],
		summable:   summable,
		unsummable: unsummable,
		interval:   intervalTime,
	}, nil
}

// 找出自定义数据源和参数
func (i *Issu) getUserDefinedDatasourceInfos(connect *sql.DB, db, tableName string) ([]*DatasourceInfo, error) {
	tables, err := getTables(connect, db, tableName)
	if err != nil {
		log.Info(err)
		return nil, nil
	}

	aggTables := []string{}
	aggSuffix := "_agg"
	for _, t := range tables {
		if strings.HasSuffix(t, aggSuffix) {
			aggTables = append(aggTables, t[:len(t)-len(aggSuffix)])
		}
	}

	dSInfos := []*DatasourceInfo{}
	for _, name := range aggTables {
		ds, err := i.getDatasourceInfo(connect, db, name+"_mv")
		if err != nil {
			return nil, err
		}
		dSInfos = append(dSInfos, ds)
	}

	return dSInfos, nil
}

func (i *Issu) addColumnDatasource(connect *sql.DB, d *DatasourceInfo, isMapTable bool, isAppTable bool) ([]*ColumnAdd, error) {
	// mod table agg, global
	dones := []*ColumnAdd{}

	columnDatasourceAdds := []*ColumnDatasourceAdd{}

	for _, version := range AllDatasourceAdds {
		columnDatasourceAdds = append(columnDatasourceAdds, version...)
	}

	for _, add := range columnDatasourceAdds {
		version, err := i.getTableVersion(connect, d.db, d.name)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			continue
		}
		if (add.OnlyAppTable && !isMapTable) || (add.OnlyAppTable && !isAppTable) {
			continue
		}
		aggTable := d.name + "_agg"
		addColumn := &ColumnAdd{
			Db:         d.db,
			Table:      aggTable,
			ColumnName: add.ColumnName,
			ColumnType: add.ColumnType,
		}
		if err := i.addColumn(connect, addColumn); err != nil {
			return dones, err
		}
		if add.OldColumnName != "" {
			sql := fmt.Sprintf("ALTER TABLE %s.`%s` update %s=%s WHERE 1",
				d.db, aggTable, addColumn.ColumnName, add.OldColumnName)
			log.Info("datasource copy column: ", sql)
			_, err = connect.Exec(sql)
		}
		dones = append(dones, addColumn)
	}

	if len(dones) == 0 {
		log.Infof("datasource db(%s) table(%s) already updated.", d.db, d.name)
		return nil, nil
	}

	// drop table mv
	sql := fmt.Sprintf("DROP TABLE IF EXISTS %s.`%s`", d.db, d.name+"_mv")
	log.Info(sql)
	_, err := connect.Exec(sql)
	if err != nil {
		return nil, err
	}

	lastDotIndex := strings.LastIndex(d.name, ".")
	if lastDotIndex < 0 {
		return nil, fmt.Errorf("invalid table name %s", d.name)
	}
	dstTableName := d.name[lastDotIndex+1:]
	rawTable := flow_metrics.GetMetricsTables(ckdb.MergeTree, common.CK_VERSION, ckdb.DF_CLUSTER, ckdb.DF_STORAGE_POLICY, 7, 1, 7, 1, i.cfg.GetCKDBColdStorages())[flow_metrics.MetricsTableNameToID(d.name[:lastDotIndex+1]+d.baseTable)]
	// create table mv
	createMvSql := datasource.MakeMVTableCreateSQL(
		rawTable, dstTableName,
		d.summable, d.unsummable, d.interval)
	log.Info(createMvSql)
	_, err = connect.Exec(createMvSql)
	if err != nil {
		return nil, err
	}

	// drop table local
	sql = fmt.Sprintf("DROP TABLE IF EXISTS %s.`%s`", d.db, d.name+"_local")
	log.Info(sql)
	_, err = connect.Exec(sql)
	if err != nil {
		return nil, err
	}

	// create table local
	createLocalSql := datasource.MakeCreateTableLocal(
		rawTable, dstTableName,
		d.summable, d.unsummable)
	log.Info(createLocalSql)
	_, err = connect.Exec(createLocalSql)
	if err != nil {
		return nil, err
	}

	// create table global
	createGlobalSql := datasource.MakeGlobalTableCreateSQL(rawTable, dstTableName)
	log.Info(createGlobalSql)
	_, err = connect.Exec(createGlobalSql)
	if err != nil {
		return nil, err
	}

	return dones, nil
}

func NewCKIssu(cfg *config.Config) (*Issu, error) {
	i := &Issu{
		cfg:            cfg,
		Addrs:          cfg.CKDB.ActualAddrs,
		username:       cfg.CKDBAuth.Username,
		password:       cfg.CKDBAuth.Password,
		datasourceInfo: make(map[string]*DatasourceInfo),
	}

	i.columnAdds = []*ColumnAdd{}
	for _, versionAdd := range AllColumnAdds {
		for _, adds := range versionAdd {
			i.columnAdds = append(i.columnAdds, getColumnAdds(adds)...)
		}
	}

	for _, v := range AllIndexAdds {
		i.indexAdds = append(i.indexAdds, v...)
	}

	for _, v := range AllColumnMods {
		i.columnMods = append(i.columnMods, v...)
	}

	for _, v := range AllColumnRenames {
		i.columnRenames = append(i.columnRenames, v...)
	}

	for _, v := range AllColumnDrops {
		i.columnDrops = append(i.columnDrops, v...)
	}

	for _, v := range AllTableModTTLs {
		i.modTTLs = append(i.modTTLs, v...)
	}

	var err error
	i.Connections, err = common.NewCKConnections(i.Addrs, i.username, i.password)
	if err != nil {
		return nil, err
	}

	return i, nil
}

// called in server/ingester/ingester/ingester.go, executed before Start()
func (i *Issu) RunRenameTable(ds *datasource.DatasourceManager) error {
	err := i.renameTablesV65(ds)
	log.Info("renameTablesV65", err)
	i.tableRenames = AllTableRenames
	for _, connection := range i.Connections {
		oldVersion, err := i.getTableVersion(connection, "flow_log", "l4_flow_log_local")
		if err != nil {
			return err
		}
		if strings.Compare(oldVersion, "v6.5") >= 0 || oldVersion == "" {
			continue
		}
		for _, tableRename := range i.tableRenames {
			if err := i.renameTable(connection, tableRename); err != nil {
				return err
			}
		}
		if err := i.renameUserDefineDatasource(connection, ds); err != nil {
			log.Warning(err)
		}
	}
	return nil
}

func (i *Issu) renameTablesV65(ds *datasource.DatasourceManager) error {
	for _, connection := range i.Connections {
		oldVersion, err := i.getTableVersion(connection, "flow_log", "l7_flow_log_local")
		if err != nil {
			return err
		}
		if strings.Compare(oldVersion, "v6.5.1") >= 0 {
			continue
		}

		for _, tableRename := range TableRenames65 {
			if err := i.renameTable(connection, tableRename); err != nil {
				return err
			}
		}

		for idx, oldTable := range []string{"vtap_flow_port", "vtap_flow_edge_port", "vtap_app_port", "vtap_app_edge_port"} {
			newTables := []string{"network", "network_map", "application", "application_map"}
			datasourceInfos, err := i.getUserDefinedDatasourceInfos(connection, "flow_metrics", oldTable)
			if err != nil {
				return err
			}
			for _, dsInfo := range datasourceInfos {
				log.Infof("rename datasource: %+v", dsInfo)
				// rename agg tables
				if err := i.renameTable(connection, &TableRename{
					OldDb:     dsInfo.db,
					OldTables: []string{dsInfo.name + "_agg", dsInfo.name + "_mv"},
					NewDb:     ckdb.METRICS_DB,
					NewTables: []string{strings.Replace(dsInfo.name, oldTable, newTables[idx], 1) + "_agg", strings.Replace(dsInfo.name, oldTable, newTables[idx], 1) + "_mv"},
				}); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (i *Issu) renameTable(connect *sql.DB, c *TableRename) error {
	for i := range c.OldTables {
		createDb := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", c.NewDb)
		_, err := connect.Exec(createDb)
		if err != nil {
			log.Error(err)
			return err
		}

		// RENAME TABLE flow_metrics."vtap_app_prot.1m_local" TO flow_metrics."application.1m_local";
		sql := fmt.Sprintf("RENAME TABLE %s.\"%s\" to %s.\"%s\"",
			c.OldDb, c.OldTables[i], c.NewDb, c.NewTables[i])
		log.Info("rename table: ", sql)
		_, err = connect.Exec(sql)
		if err != nil {
			if strings.Contains(err.Error(), "doesn't exist") {
				log.Infof("table: %s.%s rename to table: %s.\"%s\" error: %s", c.OldDb, c.OldTables[i], c.NewDb, c.NewTables[i], err)
				continue
			} else if strings.Contains(err.Error(), "already exists") {
				log.Infof("table: %s.%s rename to table: %s.\"%s\" error: %s", c.OldDb, c.OldTables[i], c.NewDb, c.NewTables[i], err)
				continue
			}
			log.Error(err)
			return err
		}
	}
	return nil
}

func (i *Issu) addColumn(connect *sql.DB, c *ColumnAdd) error {
	defaultValue := ""
	if len(c.DefaultValue) > 0 {
		defaultValue = fmt.Sprintf("default %s", c.DefaultValue)
	}
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` ADD COLUMN %s %s %s",
		c.Db, c.Table, c.ColumnName, c.ColumnType, defaultValue)
	log.Info(sql)
	_, err := connect.Exec(sql)
	if err != nil {
		// 如果已经增加，需要跳过该错误
		if strings.Contains(err.Error(), "column with this name already exists") {
			log.Infof("db: %s, table: %s error: %s", c.Db, c.Table, err)
			return nil
			// The 'metrics/metrics_local' table is created after receiving the ext_metric data. If the table field is modified just after the system starts, it will cause an error. Ignore it
		} else if strings.Contains(err.Error(), "Table ext_metrics.metrics doesn't exist") || strings.Contains(err.Error(), "Table ext_metrics.metrics_local doesn't exist") {
			log.Infof("db: %s, table: %s error: %s", c.Db, c.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}
	return nil
}

func (i *Issu) addIndex(connect *sql.DB, c *IndexAdd) error {
	indexName := c.ColumnName + "_idx"
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` ADD INDEX %s %s TYPE %s GRANULARITY 3",
		c.Db, c.Table, indexName, c.ColumnName, c.IndexType)
	log.Info(sql)
	_, err := connect.Exec(sql)
	if err != nil {
		// if it already exists, you need to skip it
		if strings.Contains(err.Error(), "index with this name already exists") {
			log.Infof("index db: %s, table: %s error: %s", c.Db, c.Table, err)
			return nil
			// The 'metrics/metrics_local' table is created after receiving the ext_metric data. If the table field is modified just after the system starts, it will cause an error. Ignore it
		} else if strings.Contains(err.Error(), "Table ext_metrics.metrics doesn't exist") || strings.Contains(err.Error(), "Table ext_metrics.metrics_local doesn't exist") {
			log.Infof("db: %s, table: %s error: %s", c.Db, c.Table, err)
			return nil
		}
		log.Error(err)
		return err
	} else {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` MATERIALIZE INDEX %s",
			c.Db, c.Table, indexName)
		log.Info(sql)
		connect.Exec(sql)
	}
	return nil
}

func (i *Issu) getColumnType(connect *sql.DB, db, table, columnName string) (string, error) {
	sql := fmt.Sprintf("SELECT type FROM system.columns WHERE database='%s' AND table='%s' AND name='%s'",
		db, table, columnName)
	rows, err := connect.Query(sql)
	if err != nil {
		return "", err
	}
	var ctype string
	for rows.Next() {
		err := rows.Scan(&ctype)
		if err != nil {
			return "", err
		}
	}
	return ctype, nil
}

func (i *Issu) saveDatasourceInfo(connect *sql.DB, db, mvTable string) {
	if info, err := i.getDatasourceInfo(connect, db, mvTable); err == nil {
		log.Infof("save datasource info: %+v", *info)
		i.datasourceInfo[db+mvTable] = info
	}
}

// add column and copy data to new column replace rename column
func (i *Issu) renameColumnWithAddNewColumn(connect *sql.DB, cr *ColumnRename) error {
	// add new column
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` ADD COLUMN %s %s",
		cr.Db, cr.Table, cr.NewColumnName, cr.OldColumnType)
	log.Infof("rename add column: %s", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		// 如果已经增加，需要跳过该错误
		if strings.Contains(err.Error(), "column with this name already exists") {
			log.Infof("db: %s, table: %s error: %s", cr.Db, cr.Table, err)
			return nil
			// The 'metrics/metrics_local' table is created after receiving the ext_metric data. If the table field is modified just after the system starts, it will cause an error. Ignore it
		} else if strings.Contains(err.Error(), "Table ext_metrics.metrics doesn't exist") || strings.Contains(err.Error(), "Table ext_metrics.metrics_local doesn't exist") {
			log.Infof("db: %s, table: %s error: %s", cr.Db, cr.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}

	// copy data to new column
	sql = fmt.Sprintf("ALTER TABLE %s.`%s` update %s=%s WHERE 1",
		cr.Db, cr.Table, cr.NewColumnName, cr.OldColumnName)
	log.Info("rename copy column: ", sql)
	_, err = connect.Exec(sql)

	return err
}

func (i *Issu) renameColumn(connect *sql.DB, cr *ColumnRename) error {
	if cr.CheckColumnType {
		columnType, err := i.getColumnType(connect, cr.Db, cr.Table, cr.OldColumnName)
		if err != nil {
			log.Error(err)
			return err
		}
		if columnType != cr.OldColumnType.String() {
			return nil
		}
	}

	if strings.HasSuffix(cr.Table, "_local") {
		// rename first. if it fails, then drop Index and MvTable and try again. prevent accidentally deleting the MvTable.
		err := i.renameColumnWithAddNewColumn(connect, cr)
		if err == nil {
			return nil
		}
		log.Infof("rename column failed, will retry rename column later. err: %s", err)

		if cr.DropMvTable {
			mvTables, err := getMvTables(connect, cr.Db, strings.Split(cr.Table, ".")[0])
			if err != nil {
				log.Error(err)
				return err
			}
			for _, mvTable := range mvTables {
				i.saveDatasourceInfo(connect, cr.Db, mvTable)
				sql := fmt.Sprintf("DROP TABLE IF EXISTS %s.`%s`",
					cr.Db, mvTable)
				log.Info("drop mv talbe: ", sql)
				_, err := connect.Exec(sql)
				if err != nil {
					log.Error(err)
					return err
				}
			}
		}

		if cr.DropIndex {
			sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX %s_idx",
				cr.Db, cr.Table, cr.OldColumnName)
			log.Info("drop index: ", sql)
			_, err := connect.Exec(sql)
			if err != nil {
				if strings.Contains(err.Error(), "Cannot find index") {
					log.Infof("db: %s, table: %s error: %s", cr.Db, cr.Table, err)
				} else if strings.Contains(err.Error(), "is not supported by storage Distributed") {
					log.Infof("db: %s, table: %s info: %s", cr.Db, cr.Table, err)
				} else if strings.Contains(err.Error(), "doesn't exist") {
					log.Infof("db: %s, table: %s info: %s", cr.Db, cr.Table, err)
				} else {
					log.Errorf("sql: %s, error: %s", sql, err)
					return err
				}
			}
		}
		return i.renameColumnWithAddNewColumn(connect, cr)
	}

	// ALTER TABLE flow_log.l4_flow_log  RENAME COLUMN retan_tx TO retran_tx
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` RENAME COLUMN IF EXISTS %s to %s",
		cr.Db, cr.Table, cr.OldColumnName, cr.NewColumnName)
	log.Info("rename column: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		// 如果已经修改过，就会报错不存在column，需要跳过该错误
		// Code: 10. DB::Exception: Received from localhost:9000. DB::Exception: Wrong column name. Cannot find column `retan_tx` to rename.
		if strings.Contains(err.Error(), "Cannot find column") ||
			strings.Contains(err.Error(), "column with this name already exists") {
			log.Infof("db: %s, table: %s error: %s", cr.Db, cr.Table, err)
			return nil
		} else if strings.Contains(err.Error(), "doesn't exist") {
			log.Infof("db: %s, table: %s info: %s", cr.Db, cr.Table, err)
			return nil
		}
		return err
	}

	return nil
}

func (i *Issu) modColumn(connect *sql.DB, cm *ColumnMod) error {
	if cm.DropIndex {
		sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX %s_idx",
			cm.Db, cm.Table, cm.ColumnName)
		log.Info("drop index: ", sql)
		_, err := connect.Exec(sql)
		if err != nil {
			if strings.Contains(err.Error(), "Cannot find index") {
				log.Infof("db: %s, table: %s error: %s", cm.Db, cm.Table, err)
			} else if strings.Contains(err.Error(), "'DROP_INDEX' is not supported by storage Distributed") {
				log.Infof("db: %s, table: %s info: %s", cm.Db, cm.Table, err)
			} else {
				log.Error(err)
				return err
			}
		}
	}
	// ALTER TABLE flow_log.l7_flow_log  MODIFY COLUMN span_kind Nullable(UInt8);
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` MODIFY COLUMN %s %s",
		cm.Db, cm.Table, cm.ColumnName, cm.NewColumnType)
	log.Info("modify column: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		//If cannot find column, you need to skip the error
		// Code: 10. DB::Exception: Received from localhost:9000. DB::Exception: Wrong column name. Cannot find column `span_kind` to modify.
		if strings.Contains(err.Error(), "Cannot find column") {
			log.Infof("db: %s, table: %s error: %s", cm.Db, cm.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}
	return nil
}

func (i *Issu) dropColumn(connect *sql.DB, cm *ColumnDrop) error {
	// drop index first
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` DROP INDEX %s_idx", cm.Db, cm.Table, cm.ColumnName)
	log.Info("drop index: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		if strings.Contains(err.Error(), "Cannot find index") {
			log.Infof("db: %s, table: %s error: %s", cm.Db, cm.Table, err)
		} else if strings.Contains(err.Error(), "'DROP_INDEX' is not supported by storage Distributed") {
			log.Infof("db: %s, table: %s info: %s", cm.Db, cm.Table, err)
		} else {
			log.Error(err)
			return err
		}
	}

	// then drop column
	sql = fmt.Sprintf("ALTER TABLE %s.`%s` DROP COLUMN %s", cm.Db, cm.Table, cm.ColumnName)
	log.Info("drop column: ", sql)
	_, err = connect.Exec(sql)
	if err != nil {
		//If cannot find column, you need to skip the error
		// Code: 10. DB::Exception: Received from localhost:9000. DB::Exception: Wrong column name. Cannot find column `span_kind` to modify.
		if strings.Contains(err.Error(), "Cannot find column") {
			log.Infof("db: %s, table: %s error: %s", cm.Db, cm.Table, err)
			return nil
		}
		log.Error(err)
		return err
	}
	return nil
}

func getColumnDrops(columnDrops []*ColumnDrops) []*ColumnDrop {
	drops := []*ColumnDrop{}
	for _, columnDrop := range columnDrops {
		for _, d := range columnDrop.Dbs {
			for _, table := range columnDrop.Tables {
				for _, name := range columnDrop.ColumnNames {
					drops = append(drops, &ColumnDrop{
						Db:         d,
						Table:      table,
						ColumnName: name,
					})
				}
			}
		}
	}
	return drops
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
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` COMMENT COLUMN time '%s'",
		db, table, common.CK_VERSION)
	_, err := connect.Exec(sql)
	if err != nil {
		if strings.Contains(err.Error(), "doesn't exist") {
			log.Infof("db: %s, table: %s info: %s", db, table, err)
			return nil
		}
	}
	return err
}

func getColumnRenames(columnRenamess []*ColumnRenames) []*ColumnRename {
	renames := []*ColumnRename{}
	for _, columnRenames := range columnRenamess {
		for _, table := range columnRenames.Tables {
			for i, name := range columnRenames.OldColumnNames {
				renames = append(renames, &ColumnRename{
					Db:              columnRenames.Db,
					Table:           table,
					OldColumnName:   name,
					CheckColumnType: columnRenames.CheckColumnType,
					OldColumnType:   columnRenames.OldColumnTypes[i],
					NewColumnName:   columnRenames.NewColumnNames[i],
					DropIndex:       columnRenames.DropIndex,
					DropMvTable:     columnRenames.DropMvTable,
				})
			}
		}
	}
	return renames
}

func (i *Issu) renameColumns(connect *sql.DB) ([]*ColumnRename, error) {
	dones := []*ColumnRename{}
	for _, renameColumn := range i.columnRenames {
		version, err := i.getTableVersion(connect, renameColumn.Db, renameColumn.Table)
		if err != nil {
			if strings.Contains(err.Error(), "doesn't exist") {
				log.Infof("db: %s, table: %s info: %s", renameColumn.Db, renameColumn.Table, err)
				continue
			}
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

func (i *Issu) modColumns(connect *sql.DB) ([]*ColumnMod, error) {
	dones := []*ColumnMod{}
	for _, modColumn := range i.columnMods {
		version, err := i.getTableVersion(connect, modColumn.Db, modColumn.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			continue
		}
		if err := i.modColumn(connect, modColumn); err != nil {
			return dones, err
		}
		dones = append(dones, modColumn)
	}

	return dones, nil
}

func (i *Issu) dropColumns(connect *sql.DB) ([]*ColumnDrop, error) {
	dones := []*ColumnDrop{}
	for _, dropColumn := range i.columnDrops {
		version, err := i.getTableVersion(connect, dropColumn.Db, dropColumn.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			continue
		}
		if err := i.dropColumn(connect, dropColumn); err != nil {
			return dones, err
		}
		dones = append(dones, dropColumn)
	}
	return dones, nil
}

func (i *Issu) modTableTTLs(connect *sql.DB) error {
	for _, modTTL := range i.modTTLs {
		version, err := i.getTableVersion(connect, modTTL.Db, modTTL.Table)
		if err != nil {
			log.Error(err)
			continue
		}
		if version == common.CK_VERSION {
			continue
		}
		if err := i.modTTL(connect, modTTL); err != nil {
			log.Error(err)
			return err
		} else {
			if err := i.setTableVersion(connect, modTTL.Db, modTTL.Table); err != nil {
				log.Error(err)
				return err
			}
		}
	}
	return nil
}

func (i *Issu) modTTL(connect *sql.DB, mt *TableModTTL) error {
	// ALTER TABLE vtap_acl."1m_local"  MODIFY TTL time + toIntervalHour(168);
	sql := fmt.Sprintf("ALTER TABLE %s.`%s` MODIFY TTL time + toIntervalHour(%d)",
		mt.Db, mt.Table, mt.NewTTL)
	log.Info("modify TTL: ", sql)
	_, err := connect.Exec(sql)
	if err != nil {
		return err
	}
	return nil
}

func getColumnAdds(columnAdds *ColumnAdds) []*ColumnAdd {
	adds := []*ColumnAdd{}
	for _, db := range columnAdds.Dbs {
		for _, tbl := range columnAdds.Tables {
			for _, clmn := range columnAdds.ColumnNames {
				adds = append(adds, &ColumnAdd{
					Db:           db,
					Table:        tbl,
					ColumnName:   clmn,
					ColumnType:   columnAdds.ColumnType,
					DefaultValue: columnAdds.DefaultValue,
				})
			}
		}
	}
	return adds
}

func getIndexAdds(indexAddss []*IndexAdds) []*IndexAdd {
	adds := []*IndexAdd{}
	for _, indexAdds := range indexAddss {
		for _, db := range indexAdds.Dbs {
			for _, tbl := range indexAdds.Tables {
				for _, clmn := range indexAdds.ColumnNames {
					adds = append(adds, &IndexAdd{
						Db:         db,
						Table:      tbl,
						ColumnName: clmn,
						IndexType:  indexAdds.IndexType,
					})
				}
			}
		}
	}
	return adds
}

func getColumnDatasourceAdds(columnDatasourceAddss []*ColumnDatasourceAdds) []*ColumnDatasourceAdd {
	adds := []*ColumnDatasourceAdd{}
	for _, columnAdds := range columnDatasourceAddss {
		for i, name := range columnAdds.ColumnNames {
			OldColumnName := ""
			if len(columnAdds.OldColumnNames) > i {
				OldColumnName = columnAdds.OldColumnNames[i]
			}
			adds = append(adds, &ColumnDatasourceAdd{
				ColumnName:    name,
				OldColumnName: OldColumnName,
				ColumnType:    columnAdds.ColumnTypes[i],
				OnlyMapTable:  columnAdds.OnlyMapTable,
				OnlyAppTable:  columnAdds.OnlyAppTable,
			})
		}
	}
	return adds
}

func (i *Issu) addColumns(connect *sql.DB) ([]*ColumnAdd, error) {
	dones := []*ColumnAdd{}
	for _, add := range i.columnAdds {
		version, err := i.getTableVersion(connect, add.Db, add.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			log.Infof("db(%s) table(%s) already updated", add.Db, add.Table)
			continue
		}
		if err := i.addColumn(connect, add); err != nil {
			return dones, err
		}
		dones = append(dones, add)
	}

	for _, tableName := range []string{
		flow_metrics.NETWORK_1M.TableName(), flow_metrics.NETWORK_MAP_1M.TableName(),
		flow_metrics.APPLICATION_1M.TableName(), flow_metrics.APPLICATION_MAP_1M.TableName()} {
		datasourceInfos, err := i.getUserDefinedDatasourceInfos(connect, ckdb.METRICS_DB, strings.Split(tableName, ".")[0])
		if err != nil {
			log.Warning(err)
			continue
		}
		for _, dsInfo := range datasourceInfos {
			adds, err := i.addColumnDatasource(connect, dsInfo, strings.Contains(tableName, "_map"), strings.Contains(tableName, "application"))
			if err != nil {
				return nil, nil
			}
			dones = append(dones, adds...)
		}
	}

	return dones, nil
}

func (i *Issu) addIndexs(connect *sql.DB) ([]*IndexAdd, error) {
	dones := []*IndexAdd{}
	for _, add := range i.indexAdds {
		version, err := i.getTableVersion(connect, add.Db, add.Table)
		if err != nil {
			return dones, err
		}
		if version == common.CK_VERSION {
			log.Infof("db(%s) table(%s) already updated", add.Db, add.Table)
			continue
		}
		if err := i.addIndex(connect, add); err != nil {
			log.Warningf("db(%s) table(%s) add index failed.err: %s", add.Db, add.Table, err)
			continue
		}
		dones = append(dones, add)
	}
	return dones, nil
}

func (i *Issu) Start() error {
	connects := i.Connections
	if len(connects) == 0 {
		return fmt.Errorf("connections is nil")
	}
	for _, connect := range connects {
		renames, errRenames := i.renameColumns(connect)
		if errRenames != nil {
			return errRenames
		}
		mods, errMods := i.modColumns(connect)
		if errMods != nil {
			return errMods
		}

		adds, errAdds := i.addColumns(connect)
		if errAdds != nil {
			return errAdds
		}

		addIndexs, errAddIndexs := i.addIndexs(connect)
		if errAddIndexs != nil {
			log.Warning(errAddIndexs)
		}

		drops, errDrops := i.dropColumns(connect)
		if errDrops != nil {
			return errDrops
		}

		for _, cr := range renames {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		for _, cr := range mods {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		for _, cr := range adds {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		for _, cr := range addIndexs {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		for _, cr := range drops {
			if err := i.setTableVersion(connect, cr.Db, cr.Table); err != nil {
				return err
			}
		}
		go i.modTableTTLs(connect)
	}
	return nil
}

func (i *Issu) Close() error {
	if len(i.Connections) == 0 {
		return nil
	}
	return i.Connections.Close()
}

func (i *Issu) renameUserDefineDatasource(connect *sql.DB, ds *datasource.DatasourceManager) error {
	for _, tableGroup := range []string{"application", "network"} {
		datasourceInfos, err := i.getUserDefinedDatasourceInfos(connect, "flow_metrics", tableGroup)
		if err != nil {
			return err
		}
		for _, dsInfo := range datasourceInfos {
			if err := i.renameTable(connect,
				&TableRename{
					OldDb:     dsInfo.db,
					OldTables: []string{dsInfo.name + "_agg"},
					NewDb:     ckdb.METRICS_DB,
					NewTables: []string{fmt.Sprintf("%s.%s", dsInfo.db, dsInfo.name+"_agg")},
				}); err != nil {
				return err
			}
			interval := INTERVAL_HOUR
			if dsInfo.interval == ckdb.TimeFuncDay {
				interval = INTERVAL_DAY
			}
			//readd mvTable,localTable,gobalTable
			if err := ds.Handle(tableGroup, "add", dsInfo.baseTable, dsInfo.name, dsInfo.summable, dsInfo.unsummable, interval, DEFAULT_TTL); err != nil {
				return err
			}
		}
	}

	return nil
}
