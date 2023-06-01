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

#ifndef DF_USER_STRINGIFIER_H
#define DF_USER_STRINGIFIER_H

#define stack_str_hash_t	clib_bihash_8_8_t
#define stack_str_hash_init	clib_bihash_init_8_8
#define stack_str_hash_kv	clib_bihash_kv_8_8_t
#define print_hash_stack_str	print_bihash_8_8
#define stack_str_hash_search	clib_bihash_search_8_8
#define stack_str_hash_add_del	clib_bihash_add_del_8_8
#define stack_str_hash_free	clib_bihash_free_8_8
#define stack_str_hash_key_value_pair_cb	clib_bihash_foreach_key_value_pair_cb_8_8
#define stack_str_hash_foreach_key_value_pair	clib_bihash_foreach_key_value_pair_8_8

char *folded_stack_trace_string(struct bpf_tracer *t,
				struct stack_trace_key_t *v,
				const char *stack_map_name,
				stack_str_hash_t *h);
int init_stack_str_hash(stack_str_hash_t *h, const char *name);
void release_stack_strs(stack_str_hash_t *h);
stack_trace_msg_t *
resolve_and_gen_stack_trace_msg(struct bpf_tracer *t,
				struct stack_trace_key_t *v,
				const char *stack_map_name,
				stack_str_hash_t *h);

#endif /* DF_USER_STRINGIFIER_H */
