package router

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

func forwardMasterController(c *gin.Context, masterControllerName string) {
	// 获取masterControllerIP
	var controller mysql.Controller
	if ret := mysql.Db.Where("name = ?", masterControllerName).First(&controller); ret.Error != nil {
		c.String(http.StatusInternalServerError, ret.Error.Error())
		c.Abort()
		return
	}

	requestHosts := strings.Split(c.Request.Host, ":")
	c.Request.Host = strings.Replace(
		c.Request.Host, requestHosts[0], controller.IP, 1,
	)
	c.Request.URL.Scheme = "http"
	c.Request.URL.Host = c.Request.Host

	req, err := http.NewRequestWithContext(c, c.Request.Method, c.Request.URL.String(), c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}
	defer req.Body.Close()
	req.Header = c.Request.Header

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		c.Abort()
		return
	}

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, make(map[string]string))
}
