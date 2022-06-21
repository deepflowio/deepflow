// +build linux

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
