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

static const char *cgroup_str_0 =
    "8:cpuset:/docker/3386444dafd452389a80af5e5c1dc92fda06e4064770d945ea0eb3d242642bcc";
static const char *cgroup_str_1 =
    "6:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod55263d4e_9ca4_4f08_ac8e_5df9de111281.slice/cri-containerd-de8109b1bb55c08b50a9d4d3c17cffe3fc7b85b1c25b0b41dbe45e1d386bc6ba.scope";
static const char *cgroup_str_2 =
    "10:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod804d9406_ab49_4e7c_a7f1_bfddfb186df2.clice/docker-3386444dafd452389a80af5e5c1dc92fda06e4064770d945ea0eb3d242642aaa.scope";
static const char *cgroup_str_3 =
    "5:devices:/kubepods/burstable/pod599a0779-5f40-4779-9d11-82ecce3e6662/3386444dafd452389a80af5e5c1dc92fda06e4064770d945ea0eb3d242642bbb";
static const char *cgroup_str_err =
    "6:devices:/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxsystem.slice/containerd.service";

static int test_cgr_str(const char *cgr_str)
{
	char c_id[65];
	char test_str[2048];
	memset(test_str, 0, sizeof(test_str));
	memcpy(test_str, cgr_str, strlen(cgr_str));
	if (fetch_container_id_from_str(test_str, c_id, sizeof(c_id)))
		return -1;
	if (!(strlen(c_id) == 64 && strstr(test_str, c_id)))
		return -1;
	printf("\nsource : %s \n fetch : %s\n", cgr_str, c_id);
	return 0;
}

int main(void)
{
	int ret;
	ret = test_cgr_str(cgroup_str_0);
	if (ret != 0)
		return ret;
	ret = test_cgr_str(cgroup_str_1);
	if (ret != 0)
		return ret;
	ret = test_cgr_str(cgroup_str_2);
	if (ret != 0)
		return ret;
	ret = test_cgr_str(cgroup_str_3);
	if (ret != 0)
		return ret;
	ret = test_cgr_str(cgroup_str_err);
	if (ret == 0)
		return -1;

	return 0;
}
