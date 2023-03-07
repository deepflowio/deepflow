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
	QueryTime    uint64
	QueryTimeSum uint64
	QueryTimeAvg uint64 `statsd:"query_time_avg"`
	QueryTimeMax uint64 `statsd:"query_time_max"`
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

		c.ck.QueryTimeSum += qc.QueryTime
		c.ck.QueryTimeAvg = c.ck.QueryTimeSum / c.ck.QueryCount
		if qc.QueryTime > c.ck.QueryTimeMax {
			c.ck.QueryTimeMax = qc.QueryTime
		}
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
