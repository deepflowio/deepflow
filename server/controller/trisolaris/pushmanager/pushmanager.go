package pushmanager

import (
	"sync"
)

type PushManager struct {
	c *sync.Cond
}

var pushManager *PushManager = NewPushManager()

func NewPushManager() *PushManager {
	return &PushManager{
		c: sync.NewCond(&sync.Mutex{}),
	}
}

func Broadcast() {
	pushManager.c.Broadcast()
}

func Wait() {
	pushManager.c.L.Lock()
	pushManager.c.Wait()
	pushManager.c.L.Unlock()
}
