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

package tool

import (
	"testing"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
	"github.com/stretchr/testify/assert"
)

func TestAZ(t *testing.T) {
	dbItem := &model.AZ{
		Base: model.Base{
			ID:     1,
			Lcuuid: "test_lcuuid",
		},
		Name: "test_name",
	}

	t.Run("reset", func(t *testing.T) {
		a := &AZ{}
		a.reset(dbItem, nil)
		assert.Equal(t, dbItem.Lcuuid, a.Lcuuid())
		assert.Equal(t, dbItem.ID, a.ID())
		assert.Equal(t, "", a.Name())
		assert.True(t, a.IsValid())
	})

	t.Run("invalid", func(t *testing.T) {
		a := &AZ{}
		assert.False(t, a.IsValid())
	})
}

func TestNewAZCollection(t *testing.T) {
	assert.NotNil(t, NewAZCollection(nil))
}

func TestAZCollection(t *testing.T) {
	tool := NewTool(&common.Metadata{})
	c := NewAZCollection(tool)
	dbItem := &model.AZ{
		Base: model.Base{
			ID:     1,
			Lcuuid: "test_lcuuid",
		},
		Name: "test_name",
	}

	t.Run("add and get", func(t *testing.T) {
		c.Add(dbItem)
		item := c.GetByLcuuid(dbItem.Lcuuid)
		assert.Equal(t, dbItem.Lcuuid, item.Lcuuid())
		assert.Equal(t, dbItem.ID, item.ID())

		itemByID := c.GetByID(dbItem.ID)
		assert.Equal(t, dbItem.Lcuuid, itemByID.Lcuuid())
		assert.Equal(t, dbItem.ID, itemByID.ID())
	})

	t.Run("update", func(t *testing.T) {
		dbItem.Name = "updated_name"
		c.Update(dbItem)
		item := c.GetByLcuuid(dbItem.Lcuuid)
		assert.Equal(t, dbItem.Name, item.Name())
	})

	t.Run("delete", func(t *testing.T) {
		c.Delete(dbItem)
		item := c.GetByLcuuid(dbItem.Lcuuid)
		assert.False(t, item.IsValid())

		itemByID := c.GetByID(dbItem.ID)
		assert.False(t, itemByID.IsValid())
	})

	t.Run("get non-existent", func(t *testing.T) {
		item := c.GetByLcuuid("non-existent")
		assert.False(t, item.IsValid())

		itemByID := c.GetByID(999)
		assert.False(t, itemByID.IsValid())
	})
}
