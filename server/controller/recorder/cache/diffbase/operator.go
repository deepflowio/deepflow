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

package diffbase

// CollectionOperator is a non-generic interface for diffbase collection operations.
// It replaces the previous type-union constraint (CollectionConstriant) with a plain interface,
// enabling subscriber and refresher to avoid generic type parameters.
//
// All concrete XxxCollection types (e.g., AzCollection, HostCollection) satisfy this interface
// via bridge methods inherited from the generic collection[T, D] base type.
type CollectionOperator interface {
	GetResourceType() string

	// AddItems adds multiple items from DB models to the diff base.
	// dbItems must be a typed slice (e.g., []*metadbmodel.AZ) passed as interface{}.
	AddItems(seq int, dbItems interface{})

	// UpdateItem updates a single item from a DB model.
	// dbItem must be a typed pointer (e.g., *metadbmodel.AZ) passed as interface{}.
	UpdateItem(dbItem interface{})

	// DeleteByLcuuid removes an item by its lcuuid.
	DeleteByLcuuid(lcuuid string)
}
