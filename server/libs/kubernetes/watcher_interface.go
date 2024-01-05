/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
