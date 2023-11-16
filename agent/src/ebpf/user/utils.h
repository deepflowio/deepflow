/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef DF_USER_UTILS_H
#define DF_USER_UTILS_H

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)    (sizeof(a) / sizeof(a[0]))
#endif

#ifndef unlikely
#define unlikely(x)             __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x)               __builtin_expect(!!(x), 1)
#endif

#define is_set_bitmap(bitmap, idx) (bitmap[(idx) / 8] & (1 << ((idx) % 8)))
#define set_bitmap(bitmap, idx)	(bitmap[(idx) / 8] |= 1 << ((idx) % 8))
#define clear_bitmap(bitmap, idx) (bitmap[(idx) / 8] &= (~(1 << ((idx) % 8))))

#endif /* DF_USER_UTILS_H */
