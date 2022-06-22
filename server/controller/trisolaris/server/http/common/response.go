package common

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("common")

type LcResponse struct {
	OptStatus    string      `json:"OPT_STATUS"`
	Description  string      `json:"DESCRIPTION"`
	ErrorMessage string      `json:"ERROR_MESSAGE"`
	Data         interface{} `json:"DATA"`
}

type Message struct {
	Message string `json:"message,omitempty"`
}

func Response(c *gin.Context, err error, data interface{}) {
	if err == nil {
		httpCode := http.StatusOK
		if data != nil {
			c.JSON(httpCode, data)
		} else {
			c.JSON(httpCode, &Message{
				Message: "success",
			})
		}
		return
	}

	log.Debugf("err: %+v", err)
	httpCode := http.StatusInternalServerError

	c.JSON(httpCode, &Message{
		Message: err.Error(),
	})
}

func NewReponse(optStatus string, description string, data interface{}, errorMessage string) *LcResponse {
	return &LcResponse{
		OptStatus:    optStatus,
		Description:  description,
		Data:         data,
		ErrorMessage: errorMessage,
	}
}
