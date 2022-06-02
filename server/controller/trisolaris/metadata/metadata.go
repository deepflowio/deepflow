package metadata

import (
	"gorm.io/gorm"
	"sync/atomic"
	"time"

	"github.com/op/go-logging"
	"gitlab.yunshan.net/yunshan/metaflow/message/trident"

	"server/controller/trisolaris/config"
)

var log = logging.MustGetLogger("trisolaris/metadata")

type MetaData struct {
	dbDataCache    *atomic.Value // *DBDataCache 数据库缓存
	platformDataOP *PlatformDataOP
	serviceDataOP  *ServiceDataOP
	tapType        *TapType
	chPlatformData chan struct{}
	chTapType      chan struct{}
	config         *config.Config
	db             *gorm.DB
}

func NewMetaData(db *gorm.DB, cfg *config.Config) *MetaData {
	dbDataCache := &atomic.Value{}
	dbDataCache.Store(newDBDataCache())
	metaData := &MetaData{
		dbDataCache:    dbDataCache,
		tapType:        newTapType(db),
		chPlatformData: make(chan struct{}, 1),
		chTapType:      make(chan struct{}, 1),
		config:         cfg,
		db:             db,
	}
	metaData.platformDataOP = newPlatformDataOP(db, metaData)
	metaData.serviceDataOP = newServiceDataOP(metaData)
	return metaData
}

func (m *MetaData) generateDbDataCache() {
	dbDataCache := newDBDataCache()
	dbDataCache.GetDataCacheFromDB(m.db)
	m.updateDBDataCache(dbDataCache)
}

func (m *MetaData) GetDBDataCache() *DBDataCache {
	return m.dbDataCache.Load().(*DBDataCache)
}

func (m *MetaData) updateDBDataCache(d *DBDataCache) {
	m.dbDataCache.Store(d)
}

func (m *MetaData) PutChPlatformData() {
	select {
	case m.chPlatformData <- struct{}{}:
	default:
	}
}

func (m *MetaData) PutChTapType() {
	select {
	case m.chTapType <- struct{}{}:
	default:
	}
}

func (m *MetaData) GetPlatformDataOP() *PlatformDataOP {
	return m.platformDataOP
}

func (m *MetaData) GetServiceDataOP() *ServiceDataOP {
	return m.serviceDataOP
}

func (m *MetaData) GetTapTypes() []*trident.TapType {
	return m.tapType.getTapTypes()
}

func (m *MetaData) InitData() {
	m.generateDbDataCache()
	m.platformDataOP.initData()
	m.serviceDataOP.GenerateServiceData()
	m.tapType.generateTapTypes()
}

func (m *MetaData) TimedRefreshPlatformData() {
	interval := time.Duration(m.config.MetaDataRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start generate platform data from timed")
			m.generateDbDataCache()
			m.platformDataOP.GeneratePlatformData()
			m.serviceDataOP.GenerateServiceData()
			log.Info("end generate platform data from timed")
		case <-m.chPlatformData:
			log.Info("start generate platform data from rpc")
			m.generateDbDataCache()
			m.platformDataOP.GeneratePlatformData()
			m.serviceDataOP.GenerateServiceData()
			log.Info("end generate platform data from rpc")
		}
	}
}

func (m *MetaData) TimedRefreshTapType() {
	interval := time.Duration(m.config.MetaDataRefreshInterval)
	ticker := time.NewTicker(interval * time.Second).C
	for {
		select {
		case <-ticker:
			log.Info("start generate tap type from timed")
			m.tapType.generateTapTypes()
			log.Info("end generate tap type from timed")
		case <-m.chTapType:
			log.Info("start generate tap type from rpc")
			m.tapType.generateTapTypes()
			log.Info("end generate tap type from rpc")
		}
	}
}

func (m *MetaData) TimedRefreshMetaData() {
	go m.TimedRefreshPlatformData()
	go m.TimedRefreshTapType()
}
