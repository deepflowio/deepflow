package router

import (
	"server/controller/common"
	"server/controller/model"
	"server/controller/service"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

func DomainRouter(e *gin.Engine) {
	// TODO: 后续统一为v2
	e.GET("/v2/domains/:lcuuid/", getDomain)
	e.GET("/v2/domains/", getDomains)
	e.POST("/v1/domains/", createDomain)
	e.PATCH("/v1/domains/:lcuuid/", updateDomain)
	e.DELETE("/v1/domains/:lcuuid/", deleteDomain)

	e.GET("/v2/sub-domains/:lcuuid/", getSubDomain)
	e.GET("/v2/sub-domains/", getSubDomains)
	e.POST("/v2/sub-domains/", createSubDomain)
	e.PATCH("/v2/sub-domains/:lcuuid/", updateSubDomain)
	e.DELETE("/v2/sub-domains/:lcuuid/", deleteSubDomain)
}

func getDomain(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetDomains(args)
	JsonResponse(c, data, err)
}

func getDomains(c *gin.Context) {
	args := make(map[string]interface{})
	data, err := service.GetDomains(args)
	JsonResponse(c, data, err)
}

func createDomain(c *gin.Context) {
	var err error
	var domainCreate model.DomainCreate

	// 参数校验
	err = c.ShouldBindBodyWith(&domainCreate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
		return
	}

	data, err := service.CreateDomain(domainCreate)
	JsonResponse(c, data, err)
}

func updateDomain(c *gin.Context) {
	var err error
	var domainUpdate model.DomainUpdate

	// 参数校验
	err = c.ShouldBindBodyWith(&domainUpdate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	// 接收参数
	// 避免struct会有默认值，这里转为map作为函数入参
	patchMap := map[string]interface{}{}
	c.ShouldBindBodyWith(&patchMap, binding.JSON)

	lcuuid := c.Param("lcuuid")
	data, err := service.UpdateDomain(lcuuid, patchMap)
	JsonResponse(c, data, err)
}

func deleteDomain(c *gin.Context) {
	var err error

	lcuuid := c.Param("lcuuid")
	data, err := service.DeleteDomain(lcuuid)
	JsonResponse(c, data, err)
}

func getSubDomain(c *gin.Context) {
	args := make(map[string]interface{})
	args["lcuuid"] = c.Param("lcuuid")
	data, err := service.GetSubDomains(args)
	JsonResponse(c, data, err)
}

func getSubDomains(c *gin.Context) {
	args := make(map[string]interface{})
	data, err := service.GetSubDomains(args)
	JsonResponse(c, data, err)
}

func createSubDomain(c *gin.Context) {
	var err error
	var subDomainCreate model.SubDomainCreate

	// 参数校验
	err = c.ShouldBindBodyWith(&subDomainCreate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_POST_DATA, err.Error())
		return
	}

	data, err := service.CreateSubDomain(subDomainCreate)
	JsonResponse(c, data, err)
}

func deleteSubDomain(c *gin.Context) {
	var err error

	lcuuid := c.Param("lcuuid")
	data, err := service.DeleteSubDomain(lcuuid)
	JsonResponse(c, data, err)
}

func updateSubDomain(c *gin.Context) {
	var err error
	var subDomainUpdate model.SubDomainUpdate

	// 参数校验
	err = c.ShouldBindBodyWith(&subDomainUpdate, binding.JSON)
	if err != nil {
		BadRequestResponse(c, common.INVALID_PARAMETERS, err.Error())
		return
	}

	// 接收参数
	// 避免struct会有默认值，这里转为map作为函数入参
	patchMap := map[string]interface{}{}
	c.ShouldBindBodyWith(&patchMap, binding.JSON)

	lcuuid := c.Param("lcuuid")
	data, err := service.UpdateSubDomain(lcuuid, patchMap)
	JsonResponse(c, data, err)
}
