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

package service

import (
	"bytes"
	"fmt"
	"sync"
)

type prometheusLogger struct {
	pool *sync.Pool
}

func newPrometheusLogger() *prometheusLogger {
	return &prometheusLogger{
		pool: &sync.Pool{
			New: func() any {
				return new(bytes.Buffer)
			},
		},
	}
}

func (l *prometheusLogger) Log(keyvals ...interface{}) error {
	if len(keyvals)%2 != 0 {
		keyvals = append(keyvals, "") // to handle when len(keyvals) is odd
	}
	buf := l.pool.Get().(*bytes.Buffer)
	buf.WriteString("prometheus engine runtime log: ")

	for i := 0; i < len(keyvals); i += 2 {
		fmt.Fprintf(buf, "[%s=%v]", keyvals[i], keyvals[i+1])
	}
	// use `debug` level here
	log.Debug(buf.String())
	buf.Reset()
	l.pool.Put(buf)

	return nil
}
