package service

import (
	"encoding/json"
)

type ServiceError struct {
	Status  string
	Message string
}

func (e *ServiceError) Error() string {
	err, _ := json.Marshal(e)
	return string(err)
}

func NewError(status string, message string) error {
	return &ServiceError{
		Status:  status,
		Message: message,
	}
}
