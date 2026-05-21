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

#include <stdio.h>
#include <string.h>

#include "../user/utils.h"

static int check_exact_fill(void)
{
	char raw[6] = { 0 };
	char safe[6] = { 0 };
	int raw_len = snprintf(raw, sizeof(raw), "%s", "hello");
	size_t safe_len = safe_snprintf(safe, sizeof(safe), "%s", "hello");

	if (raw_len != 5 || safe_len != 5) {
		printf("exact fill length mismatch: raw=%d safe=%zu\n",
		       raw_len, safe_len);
		return -1;
	}

	if (strcmp(raw, "hello") != 0 || strcmp(safe, "hello") != 0) {
		printf("exact fill buffer mismatch: raw=\"%s\" safe=\"%s\"\n",
		       raw, safe);
		return -1;
	}

	return 0;
}

static int check_truncation(void)
{
	char raw[4] = { 0 };
	char safe[4] = { 0 };
	int raw_len = snprintf(raw, sizeof(raw), "%s", "hello");
	size_t safe_len = safe_snprintf(safe, sizeof(safe), "%s", "hello");

	if (raw_len != 5) {
		printf("unexpected raw truncation length: %d\n", raw_len);
		return -1;
	}

	if (safe_len != sizeof(safe) - 1) {
		printf("unexpected safe truncation length: %zu\n", safe_len);
		return -1;
	}

	if (strcmp(raw, "hel") != 0 || strcmp(safe, "hel") != 0) {
		printf("truncation buffer mismatch: raw=\"%s\" safe=\"%s\"\n",
		       raw, safe);
		return -1;
	}

	return 0;
}

static int check_offset_accumulation(void)
{
	char raw[4] = { 0 };
	char safe[4] = { 0 };
	int raw_len = 0;
	size_t safe_len = 0;

	raw_len += snprintf(raw + raw_len, sizeof(raw) - raw_len, "%s", "hello");
	safe_len += safe_snprintf(safe + safe_len,
				  (int64_t)sizeof(safe) - (int64_t)safe_len,
				  "%s", "hello");

	if (raw_len < sizeof(raw)) {
		printf("raw offset unexpectedly remained in bounds: %d\n", raw_len);
		return -1;
	}

	if (safe_len >= sizeof(safe)) {
		printf("safe offset escaped buffer: %zu\n", safe_len);
		return -1;
	}

	if (safe_len != sizeof(safe) - 1 || strcmp(safe, "hel") != 0) {
		printf("safe offset accumulation mismatch: len=%zu buf=\"%s\"\n",
		       safe_len, safe);
		return -1;
	}

	/*
	 * The next append would be unsafe with raw_len because it already exceeds
	 * the valid offset range after truncation. safe_len remains a valid offset.
	 */
	safe_len += safe_snprintf(safe + safe_len,
				  (int64_t)sizeof(safe) - (int64_t)safe_len,
				  "%s", "!");
	if (safe_len != sizeof(safe) - 1 || strcmp(safe, "hel") != 0) {
		printf("safe follow-up append changed truncated buffer: len=%zu buf=\"%s\"\n",
		       safe_len, safe);
		return -1;
	}

	return 0;
}

int main(void)
{
	if (check_exact_fill() != 0)
		return -1;

	if (check_truncation() != 0)
		return -1;

	if (check_offset_accumulation() != 0)
		return -1;

	printf("[OK]\n");
	return 0;
}
