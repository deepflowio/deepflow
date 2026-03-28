/**
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

package message

import (
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type Lcuuids struct {
	data []string
}

func (d *Lcuuids) GetLcuuids() []string {
	return d.data
}

func (d *Lcuuids) SetLcuuids(lcuuids []string) {
	d.data = lcuuids
}

// TODO rename to metadb
type MetadbItems[T metadbmodel.AssetResourceConstraint] struct {
	data []*T
}

func (m *MetadbItems[T]) GetMetadbItems() interface{} {
	return m.data
}

func (m *MetadbItems[T]) SetMetadbItems(items interface{}) {
	m.data = items.([]*T)
}

type Key struct {
	ID     int
	Lcuuid string
}

func (k *Key) SetID(id int) {
	k.ID = id
}

func (k *Key) GetID() int {
	return k.ID
}

func (k *Key) SetLcuuid(lcuuid string) {
	k.Lcuuid = lcuuid
}

func (k *Key) GetLcuuid() string {
	return k.Lcuuid
}

type Fields[T any] struct {
	data *T
}

func (f *Fields[T]) SetFields(data interface{}) {
	f.data = data.(*T)
}

func (f *Fields[T]) GetFields() interface{} {
	return f.data
}

type fieldDetail[T any] struct {
	different bool
	new       T
	old       T
}

func (d *fieldDetail[T]) Set(old, new T) {
	d.SetDifferent()
	d.new = new
	d.old = old
}

func (d *fieldDetail[T]) IsDifferent() bool {
	return d.different
}

// SetDifferent is called when new value or old value is set
func (d *fieldDetail[T]) SetDifferent() {
	d.different = true
}

func (d *fieldDetail[T]) GetNew() T {
	return d.new
}

func (d *fieldDetail[T]) SetNew(new T) {
	d.SetDifferent()
	d.new = new
}

func (d *fieldDetail[T]) GetOld() T {
	return d.old
}

func (d *fieldDetail[T]) SetOld(old T) {
	d.SetDifferent()
	d.old = old
}

type MetadbData[MT metadbmodel.AssetResourceConstraint] struct {
	new *MT
	old *MT
}

func (m *MetadbData[MT]) GetNewMetadbItem() interface{} {
	return m.new
}

func (m *MetadbData[MT]) SetNewMetadbItem(new interface{}) {
	m.new = new.(*MT)
}

func (m *MetadbData[MT]) GetOldMetadbItem() interface{} {
	return m.old
}

func (m *MetadbData[MT]) SetOldMetadbItem(old interface{}) {
	m.old = old.(*MT)
}

type AddAddition interface {
	AddNoneAddition | ProcessAddAddition
}

type DeleteAddition interface {
	DeleteNoneAddition | ProcessDeleteAddition
}

type AddNoneAddition struct {
	NoneAddition
}

type DeleteNoneAddition struct {
	NoneAddition
}

type NoneAddition struct{}

type addition[T AddAddition | DeleteAddition] struct {
	data *T
}

func (a *addition[T]) GetAddition() interface{} {
	return a.data
}

func (a *addition[T]) SetAddition(data interface{}) {
	a.data = data.(*T)
}
