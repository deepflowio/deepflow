package statsd

import (
	"sync"

	"github.com/deepflowio/deepflow/server/libs/stats"
)

func RegisterCountableForIngester(module string, countable stats.Countable, opts ...stats.Option) error {
	return stats.RegisterCountableWithModulePrefix("querier.", module, countable, opts...)
}

type ClickhouseCounter struct {
	QueryCount   uint64 `statsd:"query_count"`
	ResponseSize uint64 `statsd:"response_size"`
	RowCount     uint64 `statsd:"row_count"`
	ColumnCount  uint64 `statsd:"column_count"`
}

type Counter struct {
	ck       *ClickhouseCounter
	writeCkM *sync.Mutex
	exited   bool
}

func (c *Counter) WriteCk(qc *ClickhouseCounter) {
	go func() {
		c.writeCkM.Lock()
		defer c.writeCkM.Unlock()
		c.ck.ResponseSize += qc.ResponseSize
		c.ck.RowCount += qc.RowCount
		c.ck.ColumnCount += qc.ColumnCount
		c.ck.QueryCount++
	}()
}

func (c *Counter) GetCounter() interface{} {
	counter := &ClickhouseCounter{}
	counter, c.ck = c.ck, counter
	return counter
}

func (c *Counter) Close() {
	c.exited = true
}

func (c *Counter) Closed() bool {
	return c.exited
}

func NewCounter() *Counter {
	return &Counter{
		exited:   false,
		ck:       &ClickhouseCounter{},
		writeCkM: &sync.Mutex{},
	}
}

var QuerierCounter *Counter
