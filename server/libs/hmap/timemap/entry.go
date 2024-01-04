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

package timemap

import "fmt"

type Entry interface {
	Timestamp() uint32
	SetTimestamp(timestamp uint32)
	// Hash和Eq与timestamp没关系
	// 换句话说，调用了SetTimestamp或Merge之后，Hash不应该改变
	Hash() uint64
	Eq(other Entry) bool
	Merge(other Entry)
	Clone() Entry
	Release()
	fmt.Stringer
}
