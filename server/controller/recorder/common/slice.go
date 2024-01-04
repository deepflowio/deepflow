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
	"strconv"
	"strings"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
)

func IntSliceToString(s []int) string {
	str := ""
	for i, v := range s {
		if i == len(s)-1 {
			str += strconv.Itoa(v)
		} else {
			str += strconv.Itoa(v) + ","
		}
	}
	return str
}

func StringToIntSlice(str string) []int {
	s := []int{}
	for _, v := range strings.Split(str, ",") {
		if v != "" {
			i, err := strconv.Atoi(v)
			if err == nil {
				s = append(s, i)
			}
		}
	}
	return s
}

func ElementsSame[T constraints.Ordered](s1, s2 []T) bool {
	slices.Sort(s1)
	slices.Sort(s2)
	return slices.Equal(s1, s2)
}
