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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type ProcessIdentifier struct {
	Name        string
	PodGroupID  int
	VTapID      uint32
	CommandLine string
}

type ProcessCollectionExt struct {
	identifierToGID       map[ProcessIdentifier]uint32
	gIDToTotalCount       map[uint32]uint
	gIDToSoftDeletedCount map[uint32]uint
}

func (c *ProcessCollection) resetExt() {
	c.identifierToGID = make(map[ProcessIdentifier]uint32)
	c.gIDToTotalCount = make(map[uint32]uint)
	c.gIDToSoftDeletedCount = make(map[uint32]uint)
}

// GetGIDByIdentifier returns the GID for the given process identifier
func (c *ProcessCollection) GetGIDByIdentifier(identifier ProcessIdentifier) (uint32, bool) {
	pid, exists := c.identifierToGID[identifier]
	return pid, exists
}

// IsProcessGIDSoftDeleted checks if all processes with the given GID are soft deleted
func (c *ProcessCollection) IsProcessGIDSoftDeleted(gid uint32) bool {
	return c.gIDToSoftDeletedCount[gid] == c.gIDToTotalCount[gid]
}

// GenerateIdentifierByDBProcess generates a ProcessIdentifier from database Process model
func (c *ProcessCollection) GenerateIdentifierByDBProcess(p *metadbmodel.Process) ProcessIdentifier {
	return c.GenerateIdentifier(p.Name, p.PodGroupID, p.VTapID, p.CommandLine)
}

// GenerateIdentifier creates a ProcessIdentifier based on the process attributes
func (c *ProcessCollection) GenerateIdentifier(name string, podGroupID int, vtapID uint32, commandLine string) ProcessIdentifier {
	var identifier ProcessIdentifier
	if podGroupID == 0 {
		identifier = ProcessIdentifier{
			Name:        name,
			VTapID:      vtapID,
			CommandLine: commandLine,
		}
	} else {
		identifier = ProcessIdentifier{
			Name:       name,
			PodGroupID: podGroupID,
		}
	}
	return identifier
}

// OnAfterAdd implements CollectionExtender interface
// Maintains identifier to GID mapping and GID counters when process is added
func (c *ProcessCollection) OnAfterAdd(item *Process, dbItem *metadbmodel.Process) {
	identifier := c.GenerateIdentifierByDBProcess(dbItem)
	c.identifierToGID[identifier] = dbItem.GID
	c.gIDToTotalCount[dbItem.GID]++
}

// OnAfterUpdate implements CollectionExtender interface
// Updates mappings when process is modified
func (c *ProcessCollection) OnAfterUpdate(item *Process, dbItem *metadbmodel.Process) {
	// For now, we don't need special update logic
	// Could be implemented in the future if needed
}

// OnAfterDelete implements CollectionExtender interface
// Updates soft delete counter when process is deleted
func (c *ProcessCollection) OnAfterDelete(item *Process, dbItem *metadbmodel.Process) {
	c.gIDToSoftDeletedCount[dbItem.GID]++
}
