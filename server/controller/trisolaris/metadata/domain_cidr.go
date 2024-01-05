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

package metadata

import (
	"github.com/deepflowio/deepflow/message/trident"
)

type DomainCIDRProto struct {
	domainToCIDRs            map[string][]*trident.Cidr
	domainOrSubdomainToCIDRs map[string][]*trident.Cidr
	cidrs                    []*trident.Cidr
	simplecidrs              []*trident.Cidr
}

func newDomainCIDRProto(length int) *DomainCIDRProto {
	return &DomainCIDRProto{
		domainToCIDRs:            make(map[string][]*trident.Cidr),
		domainOrSubdomainToCIDRs: make(map[string][]*trident.Cidr),
		cidrs:                    make([]*trident.Cidr, 0, length),
		simplecidrs:              make([]*trident.Cidr, 0, length),
	}
}

func (c *DomainCIDRProto) addCIDR(cidr *trident.Cidr) {
	c.cidrs = append(c.cidrs, cidr)
}

func (c *DomainCIDRProto) addSimpleCIDR(cidr *trident.Cidr) {
	c.simplecidrs = append(c.simplecidrs, cidr)
}

func (c *DomainCIDRProto) addDomainSimpleCIDR(domain string, cidr *trident.Cidr) {
	if _, ok := c.domainToCIDRs[domain]; ok {
		c.domainToCIDRs[domain] = append(c.domainToCIDRs[domain], cidr)
	} else {
		c.domainToCIDRs[domain] = []*trident.Cidr{cidr}
	}
}

func (c *DomainCIDRProto) addSubOrDomainSimpleCIDR(domain string, cidr *trident.Cidr) {
	if _, ok := c.domainOrSubdomainToCIDRs[domain]; ok {
		c.domainOrSubdomainToCIDRs[domain] = append(c.domainOrSubdomainToCIDRs[domain], cidr)
	} else {
		c.domainOrSubdomainToCIDRs[domain] = []*trident.Cidr{cidr}
	}
}
