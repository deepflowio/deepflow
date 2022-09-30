/*
 * Copyright (c) 2022 Yunshan Networks
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

package config

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	libs "github.com/deepflowys/deepflow/server/libs/kubernetes"
	corev1 "k8s.io/api/core/v1"
)

const (
	TIMEOUT = 60
)

type Endpoint struct {
	Host string
	Port uint16
}

type Watcher struct {
	Pod                   libs.Watcher
	Endpoints             libs.Watcher
	serverPodKey          string
	clickhouseEndpointKey string
	myName                string
	myEndpoint            Endpoint
}

func NewWatcher(myName, serverPodKey, clickhouseEndpointKey string) (*Watcher, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		errMsg := fmt.Errorf("get cluster config failed: %v", err)
		log.Warning(errMsg)
		return nil, errMsg
	}
	kubernetesClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		errMsg := fmt.Errorf("create kubernetes client failed: %v", err)
		log.Warning(errMsg)
		return nil, errMsg
	}

	podWatcher, err := libs.StartCoreV1PodWatcher(context.Background(), libs.NewKubernetesWatchClient(kubernetesClient), "deepflow")
	if err != nil {
		errMsg := fmt.Errorf("create pod watcher failed: %v", err)
		log.Warning(errMsg)
		return nil, errMsg
	}

	endpointsWatcher, err := libs.StartCoreV1EndpointsWatcher(context.Background(), libs.NewKubernetesWatchClient(kubernetesClient), "deepflow")
	if err != nil {
		errMsg := fmt.Errorf("create endpoints watcher failed: %v", err)
		log.Warning(errMsg)
		return nil, errMsg
	}

	watcher := &Watcher{podWatcher, endpointsWatcher, serverPodKey, clickhouseEndpointKey, myName, Endpoint{}}
	watcher.myEndpoint, err = watcher.GetMyClickhouseEndpoint()
	if err != nil {
		return nil, err
	}
	go watcher.Run()
	return watcher, nil
}

func (w *Watcher) Run() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		endpoint, err := w.GetMyClickhouseEndpoint()
		if err != nil {
			panic(err)
		}
		if endpoint != w.myEndpoint {
			panic(fmt.Sprintf("endpoint change from %v to %v", w.myEndpoint, endpoint))
		}
	}
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}

// How to get my clickhouse endpoint:
// 1, Get a list of all 'deepflow-server' pods, and sort by name to find the 'index' of myself pod in it
// 2. Get the list and total 'len' of all clickhouse endpoints, and sort by IP
// 3, my corresponding 'clickhouse endpoint' is on position 'index%len'  in the 'clickhouse endpoints list'
func (w *Watcher) GetMyClickhouseEndpoint() (Endpoint, error) {
	endpoint := Endpoint{}
	podNames, err := w.getPodNames(w.serverPodKey)
	if err != nil {
		return endpoint, err
	}
	myIndex := indexOf(podNames, w.myName)
	if myIndex < 0 {
		return endpoint, fmt.Errorf("can't find my pod name(%s) in pods(%v)", w.myName, podNames)
	}
	endpoints, err := w.getEndpoints(w.clickhouseEndpointKey)
	if err != nil {
		return endpoint, err
	}
	endpoint = endpoints[myIndex%len(endpoints)]

	return endpoint, nil
}

func (w *Watcher) GetClickhouseEndpointsWithoutMyself() ([]Endpoint, error) {
	endpoints, err := w.getEndpoints(w.clickhouseEndpointKey)
	if err != nil {
		return nil, err
	}
	endpointsWithoutMyself := []Endpoint{}
	for _, e := range endpoints {
		if e == w.myEndpoint {
			continue
		}
		endpointsWithoutMyself = append(endpointsWithoutMyself, e)
	}
	return endpointsWithoutMyself, nil
}

func (w *Watcher) getPodNames(key string) ([]string, error) {
	for i := 0; i < TIMEOUT; i++ {
		entries := w.Pod.Entries()
		pods := []string{}
		for _, v := range entries {
			if p, ok := v.(*corev1.Pod); ok {
				pod := p.GetName()
				if strings.Contains(pod, key) {
					pods = append(pods, pod)
				}
			}
		}

		if len(pods) == 0 {
			time.Sleep(time.Second)
			continue
		}

		sort.Slice(pods, func(i, j int) bool {
			return pods[i] < pods[j]
		})
		log.Debugf("get pods %v", pods)
		return pods, nil
	}
	return nil, fmt.Errorf("get pod(%s) empty, timeout is %ds", key, TIMEOUT)
}

func (w *Watcher) getEndpoints(key string) ([]Endpoint, error) {
	for i := 0; i < TIMEOUT; i++ {
		entries := w.Endpoints.Entries()
		endpoints := []Endpoint{}
		for _, v := range entries {
			e, ok := v.(*corev1.Endpoints)
			if !ok {
				continue
			}
			ep := e.GetName()
			if ep != key {
				continue
			}
			for _, v := range e.Subsets {
				port := uint16(0)
				for _, p := range v.Ports {
					if p.Name == "tcp-port" || p.Name == "clickhouse" {
						port = uint16(p.Port)
						break
					}
				}
				if port == 0 {
					continue
				}
				for _, v := range v.Addresses {
					endpoints = append(endpoints, Endpoint{v.IP, port})
				}
			}
		}

		if len(endpoints) == 0 {
			time.Sleep(time.Second)
			continue
		}

		sort.Slice(endpoints, func(i, j int) bool {
			return endpoints[i].Host < endpoints[j].Host
		})
		log.Debugf("get endpoints %v", endpoints)
		return endpoints, nil
	}
	return nil, fmt.Errorf("get endpoint(%s) empty, timeout is %d", key, TIMEOUT)
}
