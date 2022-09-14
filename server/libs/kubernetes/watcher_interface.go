package kubernetes

import (
	"context"
	"time"

	"github.com/openshift/client-go/route/clientset/versioned"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

const (
	LIST_INTERVAL    = 10 * time.Minute
	REFRESH_INTERVAL = 60 * time.Minute
)

type Watcher interface {
	Type() string
	Version() uint64
	Error() string
	Entries() []runtime.Object
}

type WatcherStarter func(context.Context, *WatcherClient, string) (Watcher, error)

type WatcherClient struct {
	kubernetes *kubernetes.Clientset
	openshift  *versioned.Clientset
}

func NewKubernetesWatchClient(client *kubernetes.Clientset) *WatcherClient {
	return &WatcherClient{
		kubernetes: client,
	}
}

type DummyWatcher struct{}

func (w *DummyWatcher) Type() string {
	return "DummyWatcher"
}

func (w *DummyWatcher) Version() uint64 {
	return 0
}

func (w *DummyWatcher) Error() string {
	return ""
}

func (w *DummyWatcher) Entries() []runtime.Object {
	return []runtime.Object{}
}
