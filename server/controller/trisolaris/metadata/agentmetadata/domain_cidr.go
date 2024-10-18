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

package agentmetadata

import (
	"github.com/deepflowio/deepflow/message/agent"
)

type DomainCIDRProto struct {
	domainToCIDRs            map[string][]*agent.Cidr
	domainOrSubdomainToCIDRs map[string][]*agent.Cidr
	simplecidrs              []*agent.Cidr
}

func newDomainCIDRProto(length int) *DomainCIDRProto {
	return &DomainCIDRProto{
		domainToCIDRs:            make(map[string][]*agent.Cidr),
		domainOrSubdomainToCIDRs: make(map[string][]*agent.Cidr),
		simplecidrs:              make([]*agent.Cidr, 0, length),
	}
}

func (c *DomainCIDRProto) addSimpleCIDR(cidr *agent.Cidr) {
	c.simplecidrs = append(c.simplecidrs, cidr)
}

func (c *DomainCIDRProto) addDomainSimpleCIDR(domain string, cidr *agent.Cidr) {
	if _, ok := c.domainToCIDRs[domain]; ok {
		c.domainToCIDRs[domain] = append(c.domainToCIDRs[domain], cidr)
	} else {
		c.domainToCIDRs[domain] = []*agent.Cidr{cidr}
	}
}

func (c *DomainCIDRProto) addSubOrDomainSimpleCIDR(domain string, cidr *agent.Cidr) {
	if _, ok := c.domainOrSubdomainToCIDRs[domain]; ok {
		c.domainOrSubdomainToCIDRs[domain] = append(c.domainOrSubdomainToCIDRs[domain], cidr)
	} else {
		c.domainOrSubdomainToCIDRs[domain] = []*agent.Cidr{cidr}
	}
}
