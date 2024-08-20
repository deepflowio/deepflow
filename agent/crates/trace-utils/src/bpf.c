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

/*
 * Phony functions to make examples in this crate work
 * Linking with libbpf will replace these weak symbols
 */

#include <stdint.h>

#define UNUSED(x) (void)(x)

int __attribute__((weak))
    bpf_update_elem(int fd, const void *key, const void *value, uint64_t flags) {
    UNUSED(fd);
    UNUSED(key);
    UNUSED(value);
    UNUSED(flags);
    return 0;
}

int __attribute__((weak)) bpf_delete_elem(int fd, const void *key) {
    UNUSED(fd);
    UNUSED(key);
    return 0;
}
