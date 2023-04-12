/*
 * Copyright (c) 2023 Yunshan Networks
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

import mapset "github.com/deckarep/golang-set"

const (
	EQUAL        = "EQUAL"
	DISJOINT     = "DISJOINT"
	CONTAINED_BY = "CONTAINED_BY"
	CONTAINS     = "CONTAINS"
	INTERSECTING = "INTERSECTING"
)

// TODO(weiqiang): add comment
func CompareSets(set1, set2 mapset.Set) string {
	intersectSet := set1.Intersect(set2)
	set1DiffSet2 := set1.Difference(set2)
	set2DiffSet1 := set2.Difference(set1)

	switch {
	case set1.Equal(set2):
		return EQUAL
	case intersectSet.Cardinality() == 0:
		return DISJOINT
	case set1DiffSet2.Cardinality() == 0:
		return CONTAINED_BY
	case set2DiffSet1.Cardinality() == 0:
		return CONTAINS
	default:
		return INTERSECTING
	}
}

// TODO(weiqiang): add comment and test
func GetAddAndDelAZs(oldSet, newSet mapset.Set) (addAZs mapset.Set, delAZs mapset.Set) {
	switch CompareSets(oldSet, newSet) {
	case EQUAL:
		// addAZs = delAZs = null
	case DISJOINT:
		addAZs = newSet
		delAZs = oldSet
	case CONTAINED_BY:
		addAZs = newSet.Difference(oldSet)
		// delAZs = null
	case CONTAINS:
		// addAZs = null
		delAZs = oldSet.Difference(newSet)
	default:
		addAZs = newSet.Difference(oldSet)
		delAZs = oldSet.Difference(addAZs)
	}
	return
}
