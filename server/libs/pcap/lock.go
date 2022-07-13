//go:build linux
// +build linux

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

package pcap

import (
	"fmt"
	"os"
	"syscall"
)

type FileLock struct {
	dir string
	f   *os.File
}

func New(dir string) *FileLock {
	return &FileLock{
		dir: dir,
	}
}

func (l *FileLock) Lock() error {
	f, err := os.Open(l.dir)
	if err != nil {
		return err
	}
	l.f = f
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return fmt.Errorf("cannot flock directory %s - %s", l.dir, err)
	}
	return nil
}

func (l *FileLock) Unlock() error {
	defer l.f.Close()
	return syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
}
