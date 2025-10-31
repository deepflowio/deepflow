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

const (
	NON_DEFAULT_ORG_DATABASE_SUFFIX = "_deepflow"
	DATABASE_PREFIX_ALIGNMENT       = "%04d"
)

const (
	DEFAULT_ORG_ID  = 1
	DEFAULT_TEAM_ID = 1
)

const (
	SOURCE_MYSQL      = "MYSQL"
	SOURCE_POSTGRESQL = "POSTGRESQL"
	SQL_REPLICA       = "REPLICA (HOST '%s' PRIORITY 1)"
)
