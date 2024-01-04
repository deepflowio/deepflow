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

#include <ctype.h>
#include <arpa/inet.h>
#include <sched.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include "../user/utils.h"
#include "../user/clib.h"
#include "../user/symbol.h"
#include "../user/tracer.h"
#include "../user/probe.h"
#include "../user/table.h"
#include "../user/common.h"
#include "../user/socket.h"
#include "../user/log.h"

extern ports_bitmap_t *ports_bitmap[PROTO_NUM];

static int print_prots_bitmap(void)
{
	int i, j, count = 0;
	for (i = 0; i < ARRAY_SIZE(ports_bitmap); i++) {
		if (ports_bitmap[i]) {
			for (j = 0; j < PORT_NUM_MAX; j++) {
				if (is_set_bitmap(ports_bitmap[i]->bitmap, j)) {
					printf("Proto %s port %d allow\n",
					       get_proto_name(i), j);
					count++;
				}
			}
		}
	}

	return count;
}

static void free_prots_bitmap(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(ports_bitmap); i++) {
		if (ports_bitmap[i]) {
			clib_mem_free(ports_bitmap[i]);
			ports_bitmap[i] = NULL;
		}
	}
}

u8 bitmap[65536 / 8];
static int test_bitmap(int test_v)
{
	int err = 0;
	set_bitmap(bitmap, test_v);
	if (!is_set_bitmap(bitmap, test_v)) {
		printf("set bitmap %d failed\n", test_v);
		err++;
	}

	clear_bitmap(bitmap, test_v);
	if (is_set_bitmap(bitmap, test_v)) {
		printf("clear bitmap %d failed\n", test_v);
		err++;
	}

	return err;
}

int main(void)
{
	log_to_stdout = true;

	int err, n;
	err = set_protocol_ports_bitmap(PROTO_HTTP1, "80, 8080, 70-100");
	if (err)
		goto failed;
	printf("1 Set PROTO_HTTP1 ports \"80, 8080, 70-100\"\n");
	n = print_prots_bitmap();
	if (n != 32)
		goto failed;

	err = set_protocol_ports_bitmap(PROTO_HTTP2, "5678, 9000-9010, 10000");
	if (err)
		goto failed;
	printf("2 Set PROTO_HTTP2 ports \"5678, 9000-9010, 10000\"\n");
	n = print_prots_bitmap();
	if (n != 45)
		goto failed;

	printf("3 test set/clear bitmap [0, 65536] ...\n");
	int err_count = 0;
	int i;
	for (i = 0; i < 65536; i++)
		err_count += test_bitmap(i);
	if (err_count)
		goto failed;

	free_prots_bitmap();
	printf("[OK]\n");
	return 0;

failed:
	free_prots_bitmap();
	printf("[Failed]\n");
	return -1;
}
