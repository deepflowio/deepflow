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
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func getAscSortedNextVersions(files []fs.DirEntry, curVersion string) []string {
	vs := []string{}
	for _, f := range files {
		vs = append(vs, trimFilenameExt(f.Name()))
	}
	// asc sort: split version by ".", compare each number from first to end
	sort.Slice(vs, func(i, j int) bool {
		il := strings.Split(vs[i], ".")
		jl := strings.Split(vs[j], ".")
		return !list1GreaterList2(il, jl)
	})

	nvs := []string{}
	cvl := strings.Split(curVersion, ".")
	for _, v := range vs {
		vl := strings.Split(v, ".")
		if list1GreaterList2(vl, cvl) {
			nvs = append(nvs, v)
		}
	}
	return nvs
}

func trimFilenameExt(filename string) string {
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}

func list1GreaterList2(strList1, strList2 []string) bool {
	for i := range strList1 {
		if strList1[i] == strList2[i] {
			continue
		} else {
			in, _ := strconv.Atoi(strList1[i])
			jn, _ := strconv.Atoi(strList2[i])
			return in > jn
		}
	}
	return false
}
