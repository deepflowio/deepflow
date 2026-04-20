/**
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
	"context"
	"fmt"
	"runtime/debug"

	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("prometheus.synchronizer.common")

type ErrFunc func(...interface{}) error

func AppendErrGroupWithContext(ctx context.Context, eg *errgroup.Group, f ErrFunc, args ...interface{}) {
	eg.Go(func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				// NOTE: fatal errors such as "concurrent map read and map write" are
				// thrown by the runtime and cannot be caught here; prevent them by
				// fixing the underlying data race instead.
				log.Errorf("prometheus goroutine recovered from panic: %v\n%s", r, debug.Stack())
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return f(args...)
		}
	})
}

func AppendErrGroup(eg *errgroup.Group, f ErrFunc, args ...interface{}) {
	eg.Go(func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("prometheus goroutine recovered from panic: %v\n%s", r, debug.Stack())
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return f(args...)
	})
}
