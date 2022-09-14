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

#ifndef DF_TRACE_LIST_HEAD_H
#define DF_TRACE_LIST_HEAD_H

#include <stdlib.h>
#include <stddef.h>
#include "common.h"

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

static inline void init_list_head(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define list_first_entry(ptr, type, member) \
	container_of((ptr)->next, type, member)

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	struct list_head *tmp = head->prev;
	new->next = head;
	new->prev = head->prev;
	head->prev = new;
	tmp->next = new;
}

static inline void list_head_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}

static inline void list_del_init(struct list_head *entry)
{
	list_head_del(entry);
	init_list_head(entry);
}

#define list_for_each_safe(pos, n, head)			\
	for (pos = (head)->next, n = pos->next; pos != (head);  \
	     pos = n, n = pos->next)

#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = container_of((head)->next, typeof(*pos), member),    \
	     n = container_of(pos->member.next, typeof(*pos), member);  \
	     &pos->member != (head);                                    \
	     pos = n, n = container_of(n->member.next, typeof(*n), member))

#define list_for_each_entry(pos, head, member)                           \
	for (pos = container_of((head)->next, typeof(*pos), member);     \
	     &pos->member != (head);    				 \
	     pos = container_of(pos->member.next, typeof(*pos), member))

#endif /* DF_TRACE_LIST_HEAD_H */
