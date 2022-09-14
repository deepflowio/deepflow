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

#ifndef DF_UTILS_H
#define DF_UTILS_H

#include <arpa/inet.h>

#undef __inline
#define __inline inline __attribute__((__always_inline__))

#define ARRAY_SIZE(a)    (sizeof(a) / sizeof(a[0]))
#define BPF_LEN_CAP(x, cap) (x < cap ? (x & (cap - 1)) : cap)

#include "bpf_endian.h"

#endif /* DF_UTILS_H */
