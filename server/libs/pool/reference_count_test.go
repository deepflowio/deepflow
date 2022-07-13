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

package pool

import (
	"testing"
)

func TestReferenceCount(t *testing.T) {
	var r ReferenceCount
	r.Reset()

	r.AddReferenceCount()
	if r != 2 {
		t.Errorf("AddReferenceCount错误，预期为%d，实际为%d", 2, r)
	}
	v := r.GetReferenceCount()
	if v != 2 {
		t.Errorf("GetReferenceCount错误，预期为%d，实际为%d", 2, v)
	}

	valid := r.SubReferenceCount()
	if r != 1 || valid != true {
		t.Errorf("SubReferenceCount错误，预期为%d/%v，实际为%d/%v", 1, true, r, valid)
	}

	r.AddReferenceCount()
	r.Reset()
	if r != 1 {
		t.Errorf("Reset错误，预期为%d，实际为%d", 1, r)
	}

	valid = r.SubReferenceCount()
	if r != 0 || valid != false {
		t.Errorf("SubReferenceCount错误，预期为%d/%v，实际为%d/%v", 0, false, r, valid)
	}
	r.Reset()
	if r != 1 {
		t.Errorf("Reset错误，预期为%d，实际为%d", 1, r)
	}
}
