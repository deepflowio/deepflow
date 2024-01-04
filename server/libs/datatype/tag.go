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

package datatype

import (
	"github.com/deepflowio/deepflow/server/libs/codec"
)

type Tag struct {
	PolicyData [2]PolicyData
}

func (t *Tag) Encode(encoder *codec.SimpleEncoder) {
	t.PolicyData[0].Encode(encoder)
	t.PolicyData[1].Encode(encoder)
}

func (t *Tag) Decode(decoder *codec.SimpleDecoder) {
	t.PolicyData[0].Decode(decoder)
	t.PolicyData[1].Decode(decoder)
}

func (t *Tag) Reverse() {
	t.PolicyData[0], t.PolicyData[1] = t.PolicyData[1], t.PolicyData[0]
}
