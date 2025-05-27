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

package common

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("recorder.common")

func LogAdd(resourceType string) string {
	return fmt.Sprintf("add %s", resourceType)
}

func LogUpdate(resourceType string) string {
	return fmt.Sprintf("update %s", resourceType)
}

func LogDelete(resourceType string) string {
	return fmt.Sprintf("delete %s", resourceType)
}

type DomainNameLogPrefix struct {
	Name string
}

func NewDomainPrefix(name string) logger.Prefix {
	return &DomainNameLogPrefix{name}
}

func (p *DomainNameLogPrefix) Prefix() string {
	return fmt.Sprintf("[DomainName-%s]", p.Name)
}

type SubDomainNameLogPrefix struct {
	Name string
}

func NewSubDomainPrefix(name string) logger.Prefix {
	return &SubDomainNameLogPrefix{name}
}

func (p *SubDomainNameLogPrefix) Prefix() string {
	return fmt.Sprintf("[SubDomainName-%s]", p.Name)
}

func ResourceAForResourceBNotFound(resourceA, lcuuidA, resourceB, lcuuidB string) string {
	return fmt.Sprintf("%s (lcuuid: %s) for %s (lcuuid: %s) not found", resourceA, lcuuidA, resourceB, lcuuidB)
}
