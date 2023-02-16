/*
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

package scheduler

import (
	"context"
	"sync"
)

type Scheduler struct {
	sCtx     context.Context
	lock     sync.Mutex
	curTask  *Task
	nextTask *Task
}

func NewScheduler(sCtx context.Context) *Scheduler {
	return &Scheduler{
		sCtx: sCtx,
	}
}

func (s *Scheduler) Run() {
	for {
		if s.curTask == nil || s.curTask.Done {
			s.lock.Lock()
			if s.nextTask != nil {
				s.curTask = s.nextTask
				s.nextTask = nil
			}
			s.lock.Unlock()
		}
		if s.curTask != nil && !s.curTask.Done {
			s.curTask.Run()
		}
	}
}

// create a new task if next task is nil
func (s *Scheduler) SetNextIfNil(task *Task) *Task {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.nextTask == nil {
		s.nextTask = task
	}
	return s.nextTask
}

func (s *Scheduler) IsTaskDone(id int) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.curTask != nil && s.curTask.ID == id {
		return s.curTask.Done
	}
	if s.nextTask != nil && s.nextTask.ID != id {
		return true
	}
	return false
}

func (s *Scheduler) GetTasks() []*Task {
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
