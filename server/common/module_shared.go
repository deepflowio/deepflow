package common

import (
	"time"

	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

const QUEUE_SIZE = 1 << 16

type ControllerIngesterShared struct {
	ResourceEventQueue *queue.OverwriteQueue
}

func NewControllerIngesterShared() *ControllerIngesterShared {
	return &ControllerIngesterShared{
		ResourceEventQueue: queue.NewOverwriteQueue(
			"controller-to-ingester-resource_event", QUEUE_SIZE,
			queue.OptionFlushIndicator(time.Second*3),
			queue.OptionRelease(func(p interface{}) { p.(*eventapi.ResourceEvent).Release() })),
	}
}
