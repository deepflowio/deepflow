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

package message

type AddAddition interface {
	AddNoneAddition | AddedProcessesAddition
}

type DeleteAddition interface {
	DeleteNoneAddition | DeletedProcessesAddition
}

type AddNoneAddition struct {
	NoneAddition
}

type DeleteNoneAddition struct {
	NoneAddition
}

type NoneAddition struct{}

type addition[T AddAddition | DeleteAddition] struct {
	data *T
}

func (a *addition[T]) GetAddition() interface{} {
	return a.data
}

func (a *addition[T]) SetAddition(data interface{}) {
	a.data = data.(*T)
}
