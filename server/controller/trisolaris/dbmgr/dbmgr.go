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

package dbmgr

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type _DBMgr[M any] struct {
	*_BaseMgr
	m M
}

// AnalyzerMgr open func
func DBMgr[M any](db *gorm.DB) *_DBMgr[M] {
	if db == nil {
		fmt.Println("DBMgr need init by db")
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &_DBMgr[M]{_BaseMgr: &_BaseMgr{DB: db, isRelated: globalIsRelated, ctx: ctx, cancel: cancel, timeout: -1}}
}

// Gets 获取批量结果
func (obj *_DBMgr[M]) Gets() (results []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Find(&results).Error

	return
}

func (obj *_DBMgr[M]) GetFields(fields []string) (results []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Select(fields).Find(&results).Error
	return
}

// GetBatchFromType 批量查找type类型数据
func (obj *_DBMgr[M]) GetBatchFromTypes(types []int) (results []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`type` IN (?)", types).Find(&results).Error

	return
}

// GetBatchFromIDs 批量查找id类型数据
func (obj *_DBMgr[M]) GetBatchFromIDs(ids []int) (results []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`id` IN (?)", ids).Find(&results).Error

	return
}

// GetFromID 查找id类型数据
func (obj *_DBMgr[M]) GetFromID(id int) (results *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`id` = ?", id).First(&results).Error

	return
}

// GetFromLcuuid 查找id类型数据
func (obj *_DBMgr[M]) GetFromLcuuid(lcuuid string) (results *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`lcuuid` = ?", lcuuid).First(&results).Error

	return
}

// GetFirstFromBatchIPs 查找ip相同数据
func (obj *_DBMgr[M]) GetFirstFromBatchIPs(ips []string) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`ip` IN (?)", ips).First(&result).Error

	return
}

// GetFirstFromBatchIDs 查找ids相同数据
func (obj *_DBMgr[M]) GetFirstFromBatchIDs(ids []int) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`id` IN (?)", ids).First(&result).Error

	return
}

// GetBatchFromIP 批量查找ips相同数据
func (obj *_DBMgr[M]) GetBatchFromIPs(ips []string) (result []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`ip` IN (?)", ips).Find(&result).Error

	return
}

// GetBatchFromState
func (obj *_DBMgr[M]) GetBatchFromState(state int) (result []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`state` = ?", state).Find(&result).Error

	return
}

// GetBatchFromName 查找name相同数据
func (obj *_DBMgr[M]) GetBatchFromName(name string) (result []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`name` = ?", name).Find(&result).Error

	return
}

// InsertiIgnore
func (obj *_DBMgr[M]) InsertIgnore(data *M) (err error) {
	db := obj.DB.WithContext(obj.ctx)
	err = db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(data).Error

	return
}

// GetFromPodNodeID 通过podNodeID获取内容
func (obj *_DBMgr[M]) GetFromPodNodeID(podeNodeID int) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`pod_node_id` = ?", podeNodeID).First(&result).Error
	return
}

// GetFromControllerIP 通过ControllerIP获取内容
func (obj *_DBMgr[M]) GetFromControllerIP(controllerIP string) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`controller_ip` = ?", controllerIP).First(&result).Error
	return
}

func (obj *_DBMgr[M]) GetBatchFromControllerIP(controllerIP string) (result []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`controller_ip` = ?", controllerIP).Find(&result).Error
	return
}

func (obj *_DBMgr[M]) GetBatchFromAnalyzerIP(analyzerIP string) (result []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`analyzer_ip` = ?", analyzerIP).Find(&result).Error
	return
}

// GetBatchFromPodNodeIDs 通过podNodeID获取内容
func (obj *_DBMgr[M]) GetBatchFromPodNodeIDs(podNodeIDs []int) (result []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`pod_node_id` IN (?)", podNodeIDs).Find(&result).Error
	return
}

// GetFromClusterID 通过clusterID获取内容
func (obj *_DBMgr[M]) GetFromClusterID(clusterID string) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`cluster_id` = ?", clusterID).First(&result).Error
	return
}

// GetFromName 通过name获取内容
func (obj *_DBMgr[M]) GetFromName(name string) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`name` = ?", name).First(&result).Error
	return
}

func (obj *_DBMgr[M]) GetFieldsFromName(fields []string, name string) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Select(fields).Where("`name` = ?", name).First(&result).Error

	return
}

// GetFromRegion 通过region获取内容
func (obj *_DBMgr[M]) GetFromRegion(region string) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`region` = ?", region).First(&result).Error
	return
}

func (obj *_DBMgr[M]) GetFromCAMD5(md5 string) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`ca_md5` = ?", md5).First(&result).Error
	return
}

func (obj *_DBMgr[M]) GetBatchFromRegion(region string) (result []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`region` = ?", region).Find(&result).Error
	return
}

func (obj *_DBMgr[M]) GetVInterfaceFromDeviceIDs(ctrlMac string, region string, deviceType int, deviceIDs []int) (result *M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`mac` = ?", ctrlMac).Where(
		"`region` = ?", region).Where("`devicetype` = ?", deviceType).Where(
		"`deviceid`in (?)", deviceIDs).First(&result).Error

	return
}

func (obj *_DBMgr[M]) GetBatchVInterfaceFromIDs(ctrlMac string, region string, deviceType int, ids []int) (result []*M, err error) {
	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where("`mac` = ?", ctrlMac).Where(
		"`region` = ?", region).Where("`devicetype` = ?", deviceType).Where(
		"`id`in (?)", ids).Find(&result).Error

	return
}

// DeleteBatchFromID 批量删除
func (obj *_DBMgr[M]) DeleteBatchFromID(ids []int) (err error) {
	err = obj.DB.WithContext(obj.ctx).Delete(obj.m, ids).Error
	return
}

func (obj *_DBMgr[M]) Insert(data *M) (err error) {
	err = obj.DB.WithContext(obj.ctx).Create(data).Error
	return
}

func (obj *_DBMgr[M]) InsertBulk(data []*M) (err error) {
	err = obj.DB.WithContext(obj.ctx).Create(&data).Error
	return
}

func (obj *_DBMgr[M]) UpdateBulk(data []*M) (err error) {
	for _, d := range data {
		err = obj.DB.WithContext(obj.ctx).Save(&d).Error
	}
	return
}

func (obj *_DBMgr[M]) Updates(data *M, values map[string]interface{}) (err error) {
	err = obj.DB.WithContext(obj.ctx).Model(&data).Updates(values).Error
	return
}

// WithIP ip获取
func (obj *_DBMgr[M]) WithIP(ip string) Option {
	return optionFunc(func(o *options) { o.query["ip"] = ip })
}

// WithName name获取
func (obj *_DBMgr[M]) WithName(name string) Option {
	return optionFunc(func(o *options) { o.query["name"] = name })
}

func (obj *_DBMgr[M]) WithType(dType int) Option {
	return optionFunc(func(o *options) { o.query["type"] = dType })
}

func (obj *_DBMgr[M]) WithCtrlIP(ctrlIP string) Option {
	return optionFunc(func(o *options) { o.query["ctrl_ip"] = ctrlIP })
}

func (obj *_DBMgr[M]) WithCtrlMac(ctrlMac string) Option {
	return optionFunc(func(o *options) { o.query["ctrl_mac"] = ctrlMac })
}

// GetByOption 功能选项模式获取
func (obj *_DBMgr[M]) GetByOption(opts ...Option) (result *M, err error) {
	options := options{
		query: make(map[string]interface{}, len(opts)),
	}
	for _, o := range opts {
		o.apply(&options)
	}

	err = obj.DB.WithContext(obj.ctx).Model(obj.m).Where(options.query).First(&result).Error
	return
}
func (obj *_DBMgr[M]) Save(data *M) (err error) {
	err = obj.DB.WithContext(obj.ctx).Save(data).Error
	return
}
