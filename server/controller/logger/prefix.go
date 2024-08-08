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

package logger

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/logger/blocker"
)

// Prefix is an interface that can be implemented by types that want to provide a prefix to a log message.
type Prefix interface {
	// Prefix returns the prefix string.
	Prefix() string
}

var defaultORGID = 1

// ORGPrefix implements LogPrefix to provide a prefix for log messages with an organization ID.
type ORGPrefix struct {
	ID int
}

func NewORGPrefix(id int) Prefix {
	return &ORGPrefix{id}
}

func (o *ORGPrefix) Prefix() string {
	if blocker.IfBlockORGID(o.ID) {
		return ""
	}
	return fmt.Sprintf("[ORGID-%d]", o.ID)
}

type TeamPrefix struct {
	ID int
}

func NewTeamPrefix(id int) Prefix {
	return &TeamPrefix{id}
}

func (t *TeamPrefix) Prefix() string {
	if blocker.IfBlockTeamID(t.ID) {
		return ""
	}
	return fmt.Sprintf("[TeamID-%d]", t.ID)
}
