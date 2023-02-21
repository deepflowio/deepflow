package decoder

import (
	"context"
	"net"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/profile/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/pyroscope-io/pyroscope/pkg/storage"
)

type Parser struct {
	profileName string
	vtapID      uint16
	IP          net.IP

	// profileWriter.Write
	callBack func(interface{})

	platformData *grpc.PlatformInfoTable
	inTimestamp  time.Time
}

// implement storage.Putter
// triggered by input.Profile.Parse
func (p *Parser) Put(ctx context.Context, i *storage.PutInput) error {
	i.Val.IterateStacks(func(name string, self uint64, stack []string) {
		inProcesses := p.stackToInProcess(i, stack, self)
		for _, v := range inProcesses {
			p.callBack(v)
			//v.Release()
		}
	})
	return nil
}

// implement storage.MetricsExporter
// triggered by input.Profile.Parse
// not implemented due to no metrics exporter
func (p *Parser) Evaluate(i *storage.PutInput) (storage.SampleObserver, bool) {
	return nil, true
}

func (p *Parser) stackToInProcess(input *storage.PutInput, stack []string, value uint64) []*dbwriter.InProcessProfile {
	labels := input.Key.Labels()
	tagNames := make([]string, 0, len(labels))
	tagValues := make([]string, 0, len(labels))
	for k, v := range labels {
		tagNames = append(tagNames, k)
		tagValues = append(tagValues, v)
	}
	var ip4 uint32
	if ip := p.IP.To4(); ip != nil {
		ip4 = utils.IpToUint32(ip)
	}
	ret := make([]*dbwriter.InProcessProfile, 0, len(stack))
	for i := len(stack) - 1; i >= 0; i-- {
		j := dbwriter.AcquireInProcess()

		j.IsIPv4 = ip4 > 0
		if j.IsIPv4 {
			j.IP4 = ip4
		} else {
			j.IP6 = p.IP
		}

		var self int64 = 0
		if i == 0 {
			// value 都对应当前 stack 的叶子节点
			// the value is for leaf node of current stack
			self = int64(value)
		}
		var parentID uint64
		if i < len(stack)-1 {
			parentID = ret[len(stack)-1-i-1].ProfileNodeID
		}

		j.FillProfile(input, p.platformData,
			p.vtapID, p.profileName, stack[i], self,
			p.inTimestamp, spyMap[input.SpyName], parentID,
			tagNames, tagValues)

		ret = append(ret, j)
	}

	return ret
}
