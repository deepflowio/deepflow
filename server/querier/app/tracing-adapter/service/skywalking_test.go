package service

import (
	"strconv"
	"testing"

	"github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/common"
	. "github.com/smartystreets/goconvey/convey"
	"skywalking.apache.org/repo/goapi/query"
)

var skywalking_mock_data = `{
"data": {
    "trace": {
        "spans": [
            {
                "traceId": "110dc7aa-a5e8-47dd-80d4-a73a113c478b",
                "segmentId": "64b5249d-adce-473c-84b9-8e4c2dbcfa29",
                "spanId": 0,
                "parentSpanId": -1,
                "refs": [],
                "serviceCode": "ui-deployment",
                "serviceInstanceName": "v1.0.0",
                "startTime": 1694428678774,
                "endTime": 1694428678827,
                "endpointName": "/index.html",
                "type": "Exit",
                "peer": "frontend",
                "component": "ajax",
                "isError": false,
                "layer": "Http",
                "tags": [
                    {
                        "key": "http.method",
                        "value": "GET"
                    },
                    {
                        "key": "url",
                        "value": "http://frontend/homepage"
                    }
                ]
            },
            {
                "traceId": "110dc7aa-a5e8-47dd-80d4-a73a113c478b",
                "segmentId": "65853d68-adeb-4d07-9dc2-ad509c179a0d",
                "spanId": 0,
                "parentSpanId": -1,
                "refs": [
                    {
                        "traceId": "110dc7aa-a5e8-47dd-80d4-a73a113c478b",
                        "parentSegmentId": "64b5249d-adce-473c-84b9-8e4c2dbcfa29",
                        "parentSpanId": 0,
                        "type": "CROSS_PROCESS"
                    }
                ],
                "serviceCode": "front-end-deployment",
                "serviceInstanceName": "front-end",
                "startTime": 1694428678778,
                "endTime": 1694428678823,
                "endpointName": "/index",
                "type": "Entry",
                "peer": "",
                "component": "APISIX",
                "isError": false,
                "layer": "Http",
                "tags": [
                    {
                        "key": "http.method",
                        "value": "GET"
                    },
                    {
                        "key": "http.params",
                        "value": "http://front-end-deployment/index.html"
                    },
                    {
                        "key": "http.status",
                        "value": "200"
                    }
                ]
            },
            {
                "traceId": "110dc7aa-a5e8-47dd-80d4-a73a113c478b",
                "segmentId": "9be33fe4ae364a2492e4e59f56cef454.49.16944286788056842",
                "spanId": 17,
                "parentSpanId": 0,
                "refs": [],
                "serviceCode": "songs-deployment",
                "serviceInstanceName": "780aad11fdb9439985bf78ef7a7b1b42@0.0.0.0",
                "startTime": 1694428678808,
                "endTime": 1694428678808,
                "endpointName": "HikariCP/Connection/close",
                "type": "Local",
                "peer": "",
                "component": "HikariCP",
                "isError": false,
                "layer": "Unknown",
                "tags": []
            },
            {
                "traceId": "110dc7aa-a5e8-47dd-80d4-a73a113c478b",
                "segmentId": "46799e7c508f11eea149f66a6d64085b",
                "spanId": 2,
                "parentSpanId": 0,
                "refs": [],
                "serviceCode": "recommendation-deployment",
                "serviceInstanceName": "bfe5366e4f2b11eeb683f66a6d64085b",
                "startTime": 1694428678810,
                "endTime": 1694428678816,
                "endpointName": "/rating",
                "type": "Exit",
                "peer": "rating",
                "component": "Requests",
                "isError": false,
                "layer": "Http",
                "tags": [
                    {
                        "key": "http.method",
                        "value": "GET"
                    },
                    {
                        "key": "http.url",
                        "value": "http://recommendation-deployment/rating"
                    },
                    {
                        "key": "http.status.code",
                        "value": "200"
                    }
                ]
            }
        ]
    }
}}`

var skywalking_mock_exception_id = `{
"data": {
    "trace": {
        "spans": [
            {
                "traceId": "",
                "segmentId": "",
                "spanId": 0,
                "parentSpanId": 0,
                "serviceCode": "ui-deployment",
                "serviceInstanceName": "v1.0.0",
                "startTime": 1694428678810,
                "endTime": 1694428678816,
                "endpointName": "/",
                "type": "Exit",
                "peer": "frontend",
                "component": "ajax",
                "isError": false,
                "layer": "Http",
                "tags": []
            }
        ]
    }
}}`

func TestGetSkywalkingTrace(t *testing.T) {
	skywalkingAdapter := &SkyWalkingAdapter{}
	Convey("TestGetSkywalkingTrace_Success", t, func() {
		traces, err := common.Deserialize[swTraceResponse[query.Trace]]([]byte(skywalking_mock_data))
		So(err, ShouldBeNil)
		So(len(traces.Data.Trace.Spans), ShouldBeGreaterThan, 0)
		result := skywalkingAdapter.skywalkingTracesToExTraces(traces.Data.Trace)
		So(result, ShouldNotBeNil)
		So(len(result.Spans), ShouldBeGreaterThan, 0)

		for i := 0; i < len(traces.Data.Trace.Spans); i++ {
			So(result.Spans[i].ID, ShouldBeGreaterThan, 0)
			So(len(strconv.Itoa(int(result.Spans[i].ID))), ShouldBeGreaterThan, 8)
			So(result.Spans[i].Name, ShouldEqual, *traces.Data.Trace.Spans[i].EndpointName)
			So(result.Spans[i].TraceID, ShouldEqual, traces.Data.Trace.Spans[i].TraceID)
			So(result.Spans[i].AppService, ShouldEqual, traces.Data.Trace.Spans[i].ServiceCode)
			So(result.Spans[i].AppInstance, ShouldEqual, traces.Data.Trace.Spans[i].ServiceInstanceName)
			for j := 0; j < len(traces.Data.Trace.Spans[i].Tags); j++ {
				So(
					result.Spans[i].Attribute[traces.Data.Trace.Spans[i].Tags[j].Key],
					ShouldEqual,
					*traces.Data.Trace.Spans[i].Tags[j].Value,
				)
			}
		}
	})

	Convey("TestGetSkywalkingTrace_Exception_ID", t, func() {
		traces, err := common.Deserialize[swTraceResponse[query.Trace]]([]byte(skywalking_mock_exception_id))
		So(err, ShouldBeNil)
		So(len(traces.Data.Trace.Spans), ShouldBeGreaterThan, 0)
		result := skywalkingAdapter.skywalkingTracesToExTraces(traces.Data.Trace)
		So(result, ShouldNotBeNil)
		So(len(result.Spans), ShouldBeGreaterThan, 0)
		So(result.Spans[0].ID, ShouldBeGreaterThan, 0)
	})
}
