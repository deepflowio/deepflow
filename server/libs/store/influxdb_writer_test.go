package store

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/influxdata/influxdb/models"

	. "github.com/golang/mock/gomock"
	"github.com/influxdata/influxdb/client/v2"
	"gitlab.yunshan.net/yunshan/droplet-libs/store/mock_client"
)

const (
	INFLUXDB_HTTP_ADDR = "http://127.0.0.1:9086"
)

type testInfluxdbWrite struct {
	db          string
	measurement string
	tag         string
	field       string
	timestamp   uint32
}

func (w *testInfluxdbWrite) MarshalToBytes(buffer []byte) int {
	offset := 0
	size := copy(buffer[offset+4:], w.measurement)

	size += copy(buffer[offset+4+size:], w.tag)

	binary.BigEndian.PutUint32(buffer[offset:], uint32(size))
	offset += (4 + size)

	size = copy(buffer[offset+4:], w.field)
	binary.BigEndian.PutUint32(buffer[offset:], uint32(size))
	offset += (4 + size)

	offset += MarshalTimestampTo(w.timestamp, buffer[offset:])

	return offset
}

func (w *testInfluxdbWrite) GetDBName() string {
	return w.db
}

func (w *testInfluxdbWrite) Release() {
}

func (w *testInfluxdbWrite) GetMeasurement() string {
	return w.measurement
}

func (w *testInfluxdbWrite) GetTimestamp() uint32 {
	return w.timestamp
}
func newWriteItem(db, measurement, tag, field string, timestamp uint32) InfluxdbItem {
	return &testInfluxdbWrite{
		db:          db,
		measurement: measurement,
		tag:         tag,
		field:       field,
		timestamp:   timestamp,
	}
}

func newResp(tags map[string]string, fieldNames []string) *client.Response {
	resp := &client.Response{}
	resp.Err = ""

	resp.Results = make([]client.Result, 0)

	result := client.Result{}
	result.Series = make([]models.Row, 0)

	row := models.Row{}
	row.Name = "rowName"
	row.Tags = tags
	row.Columns = fieldNames
	row.Values = make([][]interface{}, 0)

	result.Series = append(result.Series, row)
	resp.Results = append(resp.Results, result)

	return resp
}

func testInfluxdbItem(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	c := mock_client.NewMockClient(ctrl)
	c.EXPECT().Query(Any()).Return(newResp(nil, nil), nil)
	c.EXPECT().Query(Any()).Return(newResp(nil, nil), nil)
	c.EXPECT().Query(Any()).Return(newResp(nil, nil), nil)
	c.EXPECT().Query(Any()).Return(newResp(nil, nil), nil)

	c.EXPECT().Ping(Any()).Return(time.Duration(0), "", nil)
	c.EXPECT().Ping(Any()).Return(time.Duration(0), "", nil)
	c.EXPECT().Ping(Any()).Return(time.Duration(0), "", nil)
	c.EXPECT().Ping(Any()).Return(time.Duration(0), "", nil)

	c.EXPECT().Write(Any()).Return(nil)
	c.EXPECT().Write(Any()).Return(nil)
	c.EXPECT().Write(Any()).Return(nil)

	defer monkey.UnpatchAll()
	monkey.Patch(client.NewHTTPClient, func(_ client.HTTPConfig) (client.Client, error) {
		return c, nil
	})

	queueCount := 3

	iw, _ := NewInfluxdbWriter(INFLUXDB_HTTP_ADDR, "", "", "", "item", "0", queueCount, 100)
	iw.SetBatchTimeout(0)
	iw.Run()
	for i := 0; i < 100; i++ {
		item := newWriteItem(fmt.Sprintf("db%d", i%queueCount),
			fmt.Sprintf("m%d", i%2),
			fmt.Sprintf(",t1=%d,t2=%d", i, i+1),
			fmt.Sprintf("f1=%di,f2=%di", i, i+1),
			uint32(time.Now().Unix())+uint32(i))
		iw.Put(i%queueCount, item)
	}
	time.Sleep(5 * time.Second / 3)
}

func testInfluxdbPoint(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()
	c := mock_client.NewMockClient(ctrl)
	c.EXPECT().Query(Any()).Return(newResp(nil, nil), nil)
	c.EXPECT().Query(Any()).Return(newResp(nil, nil), nil)
	c.EXPECT().Query(Any()).Return(newResp(nil, nil), nil)
	c.EXPECT().Query(Any()).Return(newResp(nil, nil), nil)

	c.EXPECT().Ping(Any()).Return(time.Duration(0), "", nil)
	c.EXPECT().Ping(Any()).Return(time.Duration(0), "", nil)
	c.EXPECT().Ping(Any()).Return(time.Duration(0), "", nil)
	c.EXPECT().Ping(Any()).Return(time.Duration(0), "", nil)

	c.EXPECT().Write(Any()).Return(nil)
	c.EXPECT().Write(Any()).Return(nil)
	c.EXPECT().Write(Any()).Return(nil)

	defer monkey.UnpatchAll()
	monkey.Patch(client.NewHTTPClient, func(_ client.HTTPConfig) (client.Client, error) {
		return c, nil
	})

	queueCount := 3
	iw, _ := NewInfluxdbWriter(INFLUXDB_HTTP_ADDR, "", "", "", "point", "0", queueCount, 100)
	iw.SetBatchTimeout(0)
	iw.Run()
	for i := 0; i < 100; i++ {
		tag := make(map[string]string)
		tag["t1"] = "tag1"
		tag["t2"] = "tag2"
		field := make(map[string]int64)
		field["f1"] = int64(i)
		field["f2"] = int64(i * 10)
		iw.PutPoint(i%queueCount,
			fmt.Sprintf("dbp%d", i%queueCount),
			fmt.Sprintf("m%d", i%2),
			tag,
			field,
			uint32(time.Now().Unix())+uint32(i))
	}
	time.Sleep(5 * time.Second / 3)
}
