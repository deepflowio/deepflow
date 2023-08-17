/**
 * Copyright (c) 2023 Yunshan Networks
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

package task

import (
	"context"
	"sync"
	"time"
	// "github.com/deepflowio/deepflow/server/libs/queue"
)

const (
	TASK_COUNT_PER_SCHEDULER = 2
)

type Scheduler struct {
	resourceType string
	ctx          context.Context
	cancel       context.CancelFunc // TODO

	lock     sync.Mutex
	curTask  *Task
	nextTask *Task
	toRun    chan *Task
	// taskQueue *queue.OverwriteQueue
}

func NewScheduler(ctx context.Context, resourceType string) *Scheduler {
	cCtx, cCancel := context.WithCancel(ctx)
	return &Scheduler{
		resourceType: resourceType,
		ctx:          cCtx,
		cancel:       cCancel,
		toRun:        make(chan *Task),
		// taskQueue:    queue.NewOverwriteQueue("refresh resource api cache", TASK_COUNT_PER_SCHEDULER),
	}
}

func (s *Scheduler) Start() {
	log.Infof("%s task scheduler started", s.resourceType)
	for {
		select {
		case task := <-s.toRun:
			s.lock.Lock()
			s.curTask = task
			s.nextTask = nil
			s.lock.Unlock()

			if s.curTask != nil {
				s.curTask.Run()
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	log.Infof("%s task scheduler stopped", s.resourceType)
}

func (s *Scheduler) setNextIfNil(task *Task) *Task {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.nextTask == nil {
		s.nextTask = task
	}
	go func() {
		for {
			select {
			case s.toRun <- s.nextTask:
				return
			default:
				time.Sleep(time.Second)
			}
		}
	}()
	return s.nextTask
}

func (s *Scheduler) isTaskDone(id int) (inScheduler bool, done bool) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.curTask != nil && s.curTask.ID == id {
		return true, s.curTask.Done
	}
	if s.nextTask != nil && s.nextTask.ID == id {
		return true, false
	}
	return false, true
}

func (s *Scheduler) getTasks() []*Task {
	s.lock.Lock()
	defer s.lock.Unlock()

	tasks := make([]*Task, 0)
	if s.curTask != nil {
		tasks = append(tasks, s.curTask)
	}
	if s.nextTask != nil {
		tasks = append(tasks, s.nextTask)
	}
	return tasks
}
