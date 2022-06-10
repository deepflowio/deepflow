package http

import (
	"sync"

	"github.com/gin-gonic/gin"
)

type Registration interface {
	Register(mux *gin.Engine)
}

var register = struct {
	sync.RWMutex
	r []Registration
}{}

func Register(r interface{}) {
	register.Lock()
	defer register.Unlock()

	register.r = append(register.r, (r).(Registration))
}

func RegistRouter(mux *gin.Engine) {
	for _, registered := range register.r {
		registered.Register(mux)
	}
}
