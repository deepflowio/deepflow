/*
 * Copyright (c) 2023 Yunshan Networks
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

package dbwriter

import (
	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/ingester/profile/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/utils"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("profile.dbwriter")

const (
	PROFILE_DB    = "profile"
	PROFILE_TABLE = "in_process"
)

type ClusterNode struct {
	Addr string
	Port uint16
}

type Counter struct {
	MetricsCount int64 `statsd:"metrics-count"`
	WriteErr     int64 `statsd:"write-err"`
}

type ProfileWriter struct {
	msgType           datatype.MessageType
	ckdbAddrs         []string
	ckdbUsername      string
	ckdbPassword      string
	ckdbCluster       string
	ckdbStoragePolicy string
	ckdbColdStorages  map[string]*ckdb.ColdStorage
	ttl               int
	writerConfig      baseconfig.CKWriterConfig
	ckdbWatcher       *baseconfig.Watcher
	ckWriter          *ckwriter.CKWriter

	counter *Counter
	utils.Closable
}

func (p *ProfileWriter) Write(m interface{}) {
	p.ckWriter.Put(m)
}

func NewProfileWriter(msgType datatype.MessageType, config *config.Config) (*ProfileWriter, error) {
	writer := &ProfileWriter{
		msgType:           msgType,
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ttl:               config.ProfileTTL,
		ckdbWatcher:       config.Base.CKDB.Watcher,
		writerConfig:      config.CKWriterConfig,
	}
	table := GenProfileCKTable(writer.ckdbCluster, PROFILE_DB, PROFILE_TABLE, writer.ckdbStoragePolicy, writer.ttl, ckdb.GetColdStorage(writer.ckdbColdStorages, PROFILE_DB, PROFILE_TABLE))
	ckwriter, err := ckwriter.NewCKWriter(
		writer.ckdbAddrs, writer.ckdbUsername, writer.ckdbPassword,
		PROFILE_TABLE, config.Base.CKDB.TimeZone, table,
		writer.writerConfig.QueueCount, writer.writerConfig.QueueSize,
		writer.writerConfig.BatchSize, writer.writerConfig.FlushTimeout)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	writer.ckWriter = ckwriter
	writer.ckWriter.Run()
	return writer, nil
}
