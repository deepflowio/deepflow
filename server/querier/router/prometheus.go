package router

import (
	"io/ioutil"

	"github.com/gin-gonic/gin"

	//logging "github.com/op/go-logging"
	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/prometheus"
	"github.com/deepflowio/deepflow/server/querier/service"
	"github.com/golang/snappy"

	//"github.com/k0kubun/pp"
	"github.com/prometheus/prometheus/prompb"
)

var STATUS_FIAL = "fail"

// PromQL Query API
func promQuery() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.PromQueryParams{}
		args.Context = c.Request.Context()
		args.Promql = c.Request.FormValue("query")

		// query time range will be fixed after promQL parsed, use ReadHints instead
		// ref: https://github.com/prometheus/prometheus/blob/main/prompb/types.proto#L157
		args.StartTime = c.Request.FormValue("time")
		args.EndTime = c.Request.FormValue("time")
		result, err := service.PromQueryExecute(&args, c.Request.Context())
		if err != nil {
			c.JSON(500, &common.PromQueryResponse{Error: err.Error(), Status: STATUS_FIAL})
		}
		c.JSON(200, result)
	})
}

// PromQL Range Query API
func promQueryRange() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.PromQueryParams{}
		args.Context = c.Request.Context()
		args.Promql = c.Request.FormValue("query")
		args.StartTime = c.Request.FormValue("start")
		args.EndTime = c.Request.FormValue("end")
		args.Step = c.Request.FormValue("step")
		//pp.Println(c.Request.Header.Get("Accept"))
		//pp.Println(args.Promql)

		result, err := service.PromQueryRangeExecute(&args, c.Request.Context())
		if err != nil {
			c.JSON(500, &common.PromQueryResponse{Error: err.Error(), Status: STATUS_FIAL})
		}
		//pp.Println(result)
		c.JSON(200, result)
	})
}

// RemoteRead API
func promReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		compressed, _ := ioutil.ReadAll(c.Request.Body)
		reqBuf, err := snappy.Decode(nil, compressed)
		if err != nil {
			c.JSON(500, err)
			return
		}
		var req prompb.ReadRequest
		if err := req.Unmarshal(reqBuf); err != nil {
			c.JSON(500, err)
			return
		}
		//pp.Println(req)
		resp, err := service.PromReaderExecute(&req, c.Request.Context())
		//pp.Println(resp)
		if err != nil {
			c.JSON(500, err)
			return
		}
		data, err := resp.Marshal()
		if err != nil {
			c.JSON(500, err)
			return
		}
		compressed = snappy.Encode(nil, data)
		c.Writer.Write([]byte(compressed))
	})
}

func promTagValuesReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.PromMetaParams{
			LabelName: c.Param("labelName"),
			StartTime: c.Request.FormValue("start"),
			EndTime:   c.Request.FormValue("end"),
			Context:   c.Request.Context(),
		}
		result, err := prometheus.GetTagValues(&args)
		if err != nil {
			c.JSON(500, &common.PromQueryResponse{Error: err.Error(), Status: STATUS_FIAL})
			return
		}
		c.JSON(200, result)
	})
}

func promSeriesReader() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		args := common.PromQueryParams{
			StartTime: c.Request.FormValue("start"),
			EndTime:   c.Request.FormValue("end"),
			Matchers:  c.Request.Form["match[]"],
			Context:   c.Request.Context(),
		}
		result, err := prometheus.Series(&args)
		if err != nil {
			c.JSON(500, &common.PromQueryResponse{Error: err.Error(), Status: STATUS_FIAL})
			return
		}
		c.JSON(200, result)
	})
}
