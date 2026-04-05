/*
 * Copyright (c) 2026 Yunshan Networks
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

#ifndef DF_USER_CRASH_SYMBOLIZE_H
#define DF_USER_CRASH_SYMBOLIZE_H

#include "crash_monitor.h"

/*
 * Stage-2 crash symbolization entry point.
 *
 * The input record is the fixed-size binary snapshot emitted earlier by the
 * fatal signal handler. This function runs only in normal process context, so
 * it may perform expensive operations such as opening ELF files, reading
 * external debuginfo, walking DWARF line tables, and emitting human-readable
 * logs.
 *
 * The implementation is intentionally best-effort: if a module, symbol, or
 * file:line lookup fails for one frame, the caller still gets the raw crash
 * information for that frame and processing continues for the remaining ones.
 */
int crash_symbolize_record(const struct crash_snapshot_record *record);

#endif /* DF_USER_CRASH_SYMBOLIZE_H */

