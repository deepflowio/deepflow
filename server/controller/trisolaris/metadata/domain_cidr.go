package metadata

import (
	"github.com/metaflowys/metaflow/message/trident"
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
