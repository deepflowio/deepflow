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

// Reference code: https://github.com/kubernetes/client-go/blob/master/examples/leader-election/main.go

package election

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	logging "github.com/op/go-logging"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/utils/atomicbool"
)

const (
	ID_ITEM_NUM = 4
)

type LeaderData struct {
	sync.RWMutex
	Name     string
	isValide atomicbool.Bool
}

func (l *LeaderData) SetLeader(name string) {
	l.Lock()
	l.Name = name
	l.Unlock()
}

func (l *LeaderData) GetLeader() string {
	l.RLock()
	name := l.Name
	l.RUnlock()
	return name
}

func (l *LeaderData) setValide() {
	l.isValide.Set()
}

func (l *LeaderData) getValide() bool {
	return l.isValide.IsSet()
}

var log = logging.MustGetLogger("election")
var leaderData = &LeaderData{
	isValide: atomicbool.NewBool(false),
}

func buildConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func getID() string {
	return fmt.Sprintf("%s/%s/%s/%s",
		common.GetNodeName(),
		common.GetNodeIP(),
		common.GetPodName(),
		common.GetPodIP())
}

func GetLeader() string {
	if common.IsStandaloneRunningMode() {
		// in standalone mode, the local machine is the master node because of all in one deployment
		return getID()
	}
	return leaderData.GetLeader()
}

func getCurrentLeader(ctx context.Context, lock *resourcelock.LeaseLock) string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	record, _, err := lock.Get(ctx)
	if err != nil {
		log.Error(err)
		return ""
	}

	return record.HolderIdentity
}

func checkLeaderValid(ctx context.Context, lock *resourcelock.LeaseLock) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var observedTime metav1.Time
	for {
		record, _, err := lock.Get(ctx)
		if err == nil {
			observedTime = record.RenewTime
			break
		} else {
			log.Error(err)
			time.Sleep(5 * time.Second)
		}
	}

	for {
		select {
		case <-ticker.C:
			record, _, err := lock.Get(ctx)
			if err != nil {
				log.Error(err)
				continue
			}
			if !record.RenewTime.Equal(&observedTime) {
				leaderData.setValide()
				leaderData.SetLeader(record.HolderIdentity)
				log.Infof("check leader finish, leader is %s", record.HolderIdentity)
				return
			} else {
				log.Warningf("leader(%v) validity has expired", record)
			}
		}
	}
}

func Start(ctx context.Context, cfg *config.ControllerConfig) {
	kubeconfig := cfg.Kubeconfig
	electionName := cfg.ElectionName
	electionNamespace := common.GetNameSpace()
	id := getID()
	log.Infof("election id is %s", id)
	// leader election uses the Kubernetes API by writing to a
	// lock object, which can be a LeaseLock object (preferred),
	// a ConfigMap, or an Endpoints (deprecated) object.
	// Conflicting writes are detected and each client handles those actions
	// independently.
	config, err := buildConfig(kubeconfig)
	if err != nil {
		log.Fatal(err)
	}

	client := clientset.NewForConfigOrDie(config)

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      electionName,
			Namespace: electionNamespace,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	go checkLeaderValid(ctx, lock)

	// start the leader election code loop
	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock: lock,
		// IMPORTANT: you MUST ensure that any code you have that
		// is protected by the lease must terminate **before**
		// you call cancel. Otherwise, you could have a background
		// loop still running and another process could
		// get elected before your background loop finished, violating
		// the stated goal of the lease.
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				// we're notified when we start - this is where you would
				// usually put your code
				log.Infof("%s is the leader", id)
				leaderData.SetLeader(id)
			},
			OnStoppedLeading: func() {
				// we can do cleanup here
				log.Infof("leader lost: %s", id)
				leaderData.SetLeader(getCurrentLeader(ctx, lock))
			},
			OnNewLeader: func(identity string) {
				if leaderData.getValide() {
					leaderData.SetLeader(identity)
					// we're notified when new leader elected
					log.Infof("new leader elected: %s", identity)
				}
			},
		},
	})
	if err != nil {
		log.Errorf("failed to create election: %v", err)
		time.Sleep(1 * time.Second)
		os.Exit(1)
	}
	wg := utils.GetWaitGroupInCtx(ctx)
	wg.Add(1)
	defer wg.Done()
	wait.UntilWithContext(ctx, le.Run, 0)
}
