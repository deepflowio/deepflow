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

package dbwriter

import (
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/deepflowio/deepflow/server/ingester/common"
	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/ingester/profile/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/stats"
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
	ProfilesCount int64 `statsd:"profiles-count"`
	WriteErr      int64 `statsd:"write-err"`
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
	ckWriter          *ckwriter.CKWriter
	flowTagWriter     *flow_tag.FlowTagWriter

	counter *Counter
	utils.Closable
}

func (p *ProfileWriter) GetCounter() interface{} {
	var counter *Counter
	counter, p.counter = p.counter, &Counter{}
	return counter
}

func (p *ProfileWriter) Write(m interface{}) {
	inProcess := m.(*InProcessProfile)
	inProcess.GenerateFlowTags(p.flowTagWriter.Cache)
	p.flowTagWriter.WriteFieldsAndFieldValuesInCache()

	atomic.AddInt64(&p.counter.ProfilesCount, 1)
	p.ckWriter.Put(m)
}

func NewProfileWriter(msgType datatype.MessageType, decoderIndex int, config *config.Config) (*ProfileWriter, error) {
	writer := &ProfileWriter{
		msgType:           msgType,
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ttl:               config.ProfileTTL,
		writerConfig:      config.CKWriterConfig,
		counter:           &Counter{},
	}
	table := GenProfileCKTable(writer.ckdbCluster, PROFILE_DB, PROFILE_TABLE, writer.ckdbStoragePolicy, writer.ttl, ckdb.GetColdStorage(writer.ckdbColdStorages, PROFILE_DB, PROFILE_TABLE))
	ckwriter, err := ckwriter.NewCKWriter(
		writer.ckdbAddrs,
		writer.ckdbUsername,
		writer.ckdbPassword,
		fmt.Sprintf("%s-%s-%d", msgType, PROFILE_TABLE, decoderIndex),
		config.Base.CKDB.TimeZone,
		table,
		writer.writerConfig.QueueCount,
		writer.writerConfig.QueueSize,
		writer.writerConfig.BatchSize,
		writer.writerConfig.FlushTimeout)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	flowTagWriterConfig := baseconfig.CKWriterConfig{
		QueueCount:   1,
		QueueSize:    config.CKWriterConfig.QueueSize,
		BatchSize:    config.CKWriterConfig.BatchSize,
		FlushTimeout: config.CKWriterConfig.FlushTimeout,
	}
	flowTagWriter, err := flow_tag.NewFlowTagWriter(decoderIndex, msgType.String(), PROFILE_DB, writer.ttl, ckdb.TimeFuncTwelveHour, config.Base, &flowTagWriterConfig)
	if err != nil {
		return nil, err
	}

	writer.ckWriter = ckwriter
	writer.flowTagWriter = flowTagWriter

	common.RegisterCountableForIngester("profile_writer", writer, stats.OptionStatTags{"msg": msgType.String(), "decoder_index": strconv.Itoa(decoderIndex)})
	writer.ckWriter.Run()
	return writer, nil
}
