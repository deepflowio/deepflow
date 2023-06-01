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

#include "../user/common.h"
#include "../user/mem.h"
#include "../user/log.h"
#include "../user/types.h"
#include "../user/vec.h"

__thread uword thread_index = 0;

#include "bihash_8_8.h"
#include "bihash_template.c"

#include "bihash_8_16.h"
#include "bihash_template.c"

#include "bihash_24_8.h"
#include "bihash_template.c"

