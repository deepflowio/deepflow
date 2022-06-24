package service

import (
	"server/controller/model"
	"server/controller/tagrecorder"
)

func GetVTapInterfaces(filter map[string]interface{}) (resp []model.VTapInterface, err error) {
	return tagrecorder.GetVTapInterfaces(filter)
}
