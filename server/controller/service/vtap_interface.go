package service

import (
	"github.com/metaflowys/metaflow/server/controller/model"
	"github.com/metaflowys/metaflow/server/controller/tagrecorder"
)

func GetVTapInterfaces(filter map[string]interface{}) (resp []model.VTapInterface, err error) {
	return tagrecorder.GetVTapInterfaces(filter)
}
