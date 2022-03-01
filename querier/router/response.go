package router

import (
	"metaflow/querier/common"
	"metaflow/querier/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Response struct {
	OptStatus   string      `json:"OPT_STATUS"`
	Description string      `json:"DESCRIPTION"`
	Data        interface{} `json:"DATA"`
}

func HttpResponse(c *gin.Context, httpCode int, data interface{}, optStatus string, description string) {
	c.JSON(httpCode, Response{
		OptStatus:   optStatus,
		Description: description,
		Data:        data,
	})
}

func BadRequestResponse(c *gin.Context, optStatus string, description string) {
	c.JSON(http.StatusBadRequest, Response{
		OptStatus:   optStatus,
		Description: description,
	})
}

func InternalErrorResponse(c *gin.Context, data interface{}, optStatus string, description string) {
	c.JSON(http.StatusInternalServerError, Response{
		OptStatus:   optStatus,
		Description: description,
		Data:        data,
	})
}

func JsonResponse(c *gin.Context, data interface{}, err error) {
	if err != nil {
		switch t := err.(type) {
		case *service.ServiceError:
			switch t.Status {
			case common.RESOURCE_NOT_FOUND, common.INVALID_POST_DATA, common.RESOURCE_NUM_EXCEEDED,
				common.SELECTED_RESOURCES_NUM_EXCEEDED:
				BadRequestResponse(c, t.Status, t.Message)
			case common.SERVER_ERROR:
				InternalErrorResponse(c, data, t.Status, t.Message)
			}
		default:
			InternalErrorResponse(c, data, common.FAIL, err.Error())
		}
	} else {
		HttpResponse(c, 200, data, common.SUCCESS, "")
	}
}
