package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/metaflowys/metaflow/server/querier/common"
	"github.com/metaflowys/metaflow/server/querier/service"
)

type Response struct {
	OptStatus   string      `json:"OPT_STATUS"`
	Description string      `json:"DESCRIPTION"`
	Result      interface{} `json:"result"`
	Debug       interface{} `json:"debug"`
}

func HttpResponse(c *gin.Context, httpCode int, data interface{}, debug interface{}, optStatus string, description string) {
	if debug != nil {
		c.JSON(httpCode, Response{
			OptStatus:   optStatus,
			Description: description,
			Result:      data,
			Debug:       debug,
		})
	} else {
		c.JSON(httpCode, Response{
			OptStatus:   optStatus,
			Description: description,
			Result:      data,
		})
	}
}

func BadRequestResponse(c *gin.Context, optStatus string, description string) {
	c.JSON(http.StatusBadRequest, Response{
		OptStatus:   optStatus,
		Description: description,
	})
}

func InternalErrorResponse(c *gin.Context, data interface{}, debug interface{}, optStatus string, description string) {
	c.JSON(http.StatusInternalServerError, Response{
		OptStatus:   optStatus,
		Description: description,
		Result:      data,
		Debug:       debug,
	})
}

func JsonResponse(c *gin.Context, data interface{}, debug interface{}, err error) {
	if err != nil {
		switch t := err.(type) {
		case *service.ServiceError:
			switch t.Status {
			case common.RESOURCE_NOT_FOUND, common.INVALID_POST_DATA, common.RESOURCE_NUM_EXCEEDED,
				common.SELECTED_RESOURCES_NUM_EXCEEDED:
				BadRequestResponse(c, t.Status, t.Message)
			case common.SERVER_ERROR:
				InternalErrorResponse(c, data, debug, t.Status, t.Message)
			}
		default:
			InternalErrorResponse(c, data, debug, common.FAIL, err.Error())
		}
	} else {
		HttpResponse(c, 200, data, debug, common.SUCCESS, "")
	}
}
