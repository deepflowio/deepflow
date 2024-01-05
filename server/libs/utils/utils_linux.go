//go:build linux
// +build linux

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

package utils

import (
	"os"
	"path/filepath"
	"syscall"
)

// 找出目录对应的mount路径，来自: https://stackoverflow.com/questions/4453602/how-to-find-the-mountpoint-a-file-resides-on
func Mountpoint(path string) string {
	pi, err := os.Stat(path)
	if err != nil {
		return ""
	}

	odev := pi.Sys().(*syscall.Stat_t).Dev

	for path != "/" {
		_path := filepath.Dir(path)

		in, err := os.Stat(_path)
		if err != nil {
			return ""
		}

		if odev != in.Sys().(*syscall.Stat_t).Dev {
			break
		}

		path = _path
	}

	return path
}
