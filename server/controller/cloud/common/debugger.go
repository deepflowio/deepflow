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

package common

import (
	"bufio"
	"fmt"
	"os"

	"github.com/bitly/go-simplejson"

	. "github.com/deepflowio/deepflow/server/controller/cloud/config"
)

type Debugger struct {
	logDir       string // /var/log/deepflow/cloud/<domain name>
	tmpLogDir    string // /var/log/deepflow/cloud/<domain name>/tmp
	latestLogDir string // /var/log/deepflow/cloud/<domain name>/latest
}

func NewDebugger(domainName string) *Debugger {
	logDir := fmt.Sprintf("/var/log/deepflow/cloud/%s/", domainName)
	return &Debugger{
		logDir:       logDir,
		tmpLogDir:    logDir + "tmp/",
		latestLogDir: logDir + "latest/",
	}
}

func (d *Debugger) Clear() {
	if !CONF.DebugEnabled {
		return
	}

	err := os.RemoveAll(d.logDir)
	if err != nil {
		log.Errorf("clear debug log: %s failed: %s", d.logDir, d, err.Error())
	}
}

func (d *Debugger) Refresh() {
	if !CONF.DebugEnabled {
		return
	}

	os.RemoveAll(d.latestLogDir)
	err := os.Rename(d.tmpLogDir, d.latestLogDir)
	if err != nil {
		log.Errorf("%+v refresh debug log failed: %s", d, err.Error())
	}
}

func (d *Debugger) WriteJson(filename, dividingLine string, data []*simplejson.Json) {
	if !CONF.DebugEnabled {
		return
	}

	err := d.createLogDirIfNotExists(d.tmpLogDir)
	if err != nil {
		return
	}
	file := d.tmpLogDir + filename
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Errorf("open file: %s failed: %s", file, err.Error())
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	w.WriteString(dividingLine + "\n")
	for _, item := range data {
		jsonBytes, err := item.MarshalJSON()
		if err != nil {
			log.Errorf("encode line: %+v failed: %s", item, err.Error())
			continue
		}
		jsonBytes = append(jsonBytes, []byte("\n")...)
		_, err = w.Write(jsonBytes)
		if err != nil {
			log.Errorf("buffer write line: %s failed: %s", string(jsonBytes), err.Error())
		}
	}
	err = w.Flush()
	if err != nil {
		log.Errorf("buffer flush failed: %s", err.Error())
	}
	return
}

func (d *Debugger) createLogDirIfNotExists(logDir string) error {
	if _, err := os.Stat(logDir); err == nil {
		return nil
	} else {
		err := os.MkdirAll(logDir, 0711)
		if err != nil {
			log.Errorf("create directory: %s failed: %s", logDir, err.Error())
			return err
		}
		log.Debugf("create directory: %s success", logDir)
	}
	return nil
}
