/*
 * Copyright (c) 2025 Yunshan Networks
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

#define _GNU_SOURCE
#include <ctype.h>
#include <arpa/inet.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include "clib.h"
#include "symbol.h"
#include "proc.h"
#include "tracer.h"
#include "probe.h"
#include "table.h"
#include "utils.h"
#include "socket.h"
#include "log.h"
#include "config.h"

#define MOUNT_INFO_NULL      ((struct mount_info *)0)
#define MOUNT_INFO_INVAL     ((struct mount_info *)(intptr_t)-1)
#define IS_MOUNT_INFO_ERR(ptr) (ptr == MOUNT_INFO_NULL || ptr == MOUNT_INFO_INVAL)
mount_info_hash_t mount_info_hash;
static bool inline enable_mount_info_cache(void)
{
	return (mount_info_hash.buckets != NULL);
}

int get_mount_ns_id(pid_t pid, u64 * mntns_id)
{
	if (mntns_id == NULL) {
		return -1;
	}

	char path[64];
	struct stat st;

	// Construct path: /proc/[pid]/ns/mnt
	snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);

	// Use stat() to retrieve inode number (which is the mount namespace ID)
	if (stat(path, &st) == -1) {
		ebpf_warning("The stat() call failed with error "
			     "message: \"%s\", and error number: %d.",
			     strerror(errno), errno);
		return -1;	// errno is set by stat()
	}

	*mntns_id = (u64) st.st_ino;
	return 0;
}

static bool has_mount_entry(struct list_head *mount_head, kern_dev_t s_dev)
{
	struct list_head *p, *n;
	struct mount_entry *e;
	if (!mount_head->next)
		return false;
	list_for_each_safe(p, n, mount_head) {
		e = container_of(p, struct mount_entry, list);
		if (e && e->s_dev == s_dev)
			return true;
	}

	return false;
}

void find_mount_point_path(u64 mntns_id, kern_dev_t s_dev,
			   char *mount_path, char *mount_source,
			   int mount_size, bool * is_nfs)
{
	struct list_head *p, *n;
	struct mount_entry *e;
	struct mount_info *m = mount_info_cache_lookup(0, mntns_id);
	if (IS_MOUNT_INFO_ERR(m))
		return;

	if (!m->mount_head.next) {
		AO_DEC(&m->refcount);
		return;
	}

	list_for_each_safe(p, n, &m->mount_head) {
		e = container_of(p, struct mount_entry, list);
		if (e && e->s_dev == s_dev) {
			snprintf(mount_path, mount_size, "%s", e->mount_point);
			snprintf(mount_source, mount_size, "%s",
				 e->mount_source);
			*is_nfs = e->is_nfs;
		}
	}

	AO_DEC(&m->refcount);
}

int mount_info_cache_init(const char *name)
{
	mount_info_hash_t *h = &mount_info_hash;
	memset(h, 0, sizeof(*h));
	u32 nbuckets = SYMBOLIZER_CACHES_HASH_BUCKETS_NUM;
	u64 hash_memory_size = SYMBOLIZER_CACHES_HASH_MEM_SZ;	// 2G bytes
	return mount_info_hash_init(h, (char *)name, nbuckets,
				    hash_memory_size);
}

struct mount_info *mount_info_cache_lookup(pid_t pid, u64 mntns_id)
{
	if (mntns_id == 0 && pid > 0) {
		if (get_mount_ns_id(pid, &mntns_id))
			return MOUNT_INFO_INVAL;
	}

	mount_info_hash_t *h = &mount_info_hash;
	struct mount_cache_kvp kv;
	kv.k.mntns_id = mntns_id;
	kv.v.mount_info_p = 0;
	struct mount_info *p = NULL;
	if (mount_info_hash_search(h, (mount_info_hash_kv *) & kv,
				   (mount_info_hash_kv *) & kv) == 0) {
		p = (struct mount_info *)kv.v.mount_info_p;
		AO_INC(&p->refcount);
		return p;
	}

	return MOUNT_INFO_NULL;
}

static void free_mount_info(struct mount_info *m)
{
	// Ensure there are no references before releasing.
	while (AO_GET(&m->refcount) != 1)
		CLIB_PAUSE();

	struct list_head *p, *n;
	struct mount_entry *e;
	if (!m->mount_head.next)
		goto exit;

	list_for_each_safe(p, n, &m->mount_head) {
		e = container_of(p, struct mount_entry, list);
		if (e) {
			list_head_del(&e->list);
			free(e->mount_point);
			free(e->mount_source);
			free(e);
		}
	}

exit:
	ebpf_info("Release mount information: mntns_id %lu entry_count %d"
		  " proc_count %d refcount %d\n",
		  m->mntns_id, m->entry_count, m->proc_count, m->refcount);
	free(m);
}

static int delete_mount_info_from_cache(pid_t pid, struct mount_info *m)
{
	mount_info_hash_t *h = &mount_info_hash;
	struct mount_cache_kvp kv;
	kv.k.mntns_id = m->mntns_id;
	kv.v.mount_info_p = 0;
	if (mount_info_hash_add_del
	    (h, (mount_info_hash_kv *) & kv, 0 /* delete */ )) {
		ebpf_warning("failed.(pid %d, mntns_id %lu)\n", pid,
			     m->mntns_id);
		return -1;
	}

	return 0;
}

static int add_mount_info_to_cache(pid_t pid, struct mount_info *m)
{
	mount_info_hash_t *h = &mount_info_hash;
	struct mount_cache_kvp kv;
	kv.k.mntns_id = m->mntns_id;
	kv.v.mount_info_p = pointer_to_uword(m);
	if (mount_info_hash_add_del
	    (h, (mount_info_hash_kv *) & kv, 1 /* add */ )) {
		ebpf_warning("failed.(pid %d, mntns_id %lu)\n", pid,
			     m->mntns_id);
		return -1;
	}

	return 0;
}

static int build_mount_info(pid_t pid, struct list_head *mount_head)
{
	char path[64];
	int count = 0;
	memset(mount_head, 0, sizeof(*mount_head));
	snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
	FILE *fp = fopen(path, "r");
	if (!fp) {
		ebpf_warning("fopen '%s' failed with %s(%d)\n", path,
			     strerror(errno), errno);
		return -1;
	}

	init_list_head(mount_head);
	char line[PATH_MAX];
	while (fgets(line, sizeof(line), fp)) {
		// mountinfo format ref: https://man7.org/linux/man-pages/man5/proc.5.html
		int id, parent, major, minor;
		char root[MAX_PATH_LENGTH], mount_point[MAX_PATH_LENGTH];
		char fs_type[64], mount_source[MAX_PATH_LENGTH];
		// [ID] [ParentID] [major:minor] [fs_root] [mount_point] [options] - [fs_type] [mount_source] [fs_options]
		// Example: 44 32 0:36 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
		int matched = sscanf(line, "%d %d %d:%d %s %s %*[^-] - %s %s",
				     &id, &parent, &major, &minor, root,
				     mount_point, fs_type, mount_source);
		if (matched != 8)
			continue;

		bool is_nfs = strncmp("nfs", fs_type, 3) == 0;
		/*
		 * Filter out bind mounts, because for bind mounts, the data obtained via eBPF starts from
		 * `[fs_root]`, which is already a path on the host. There's no need to translate it into
		 * the mount point path inside the container.
		 * For example, a path like `/var/lib/mysql/xxxx.data` is already a host path and does not
		 * need to be translated into `/bitnami/mysql/xxxx.data` (which is the container path).
		 * e.g.: 1729 1710 253:0 /var/lib/mysql /bitnami/mysql rw,relatime - xfs /dev/mapper/centos-root rw,attr2,inode64,noquota
		 */
		if (!(root[0] == '/' && root[1] == '\0') && !is_nfs)
			continue;

		kern_dev_t s_dev = ((major & 0xfff) << 20) | (minor & 0xfffff);
		if (has_mount_entry(mount_head, s_dev))
			continue;
		struct mount_entry *entry =
		    calloc(1, sizeof(struct mount_entry));
		if (entry == NULL) {
			ebpf_warning("calloc failed with %s(%d)\n",
				     strerror(errno), errno);
			fclose(fp);
			return -1;
		}

		entry->s_dev = s_dev;
		entry->is_nfs = is_nfs;
		entry->mount_point = strdup(mount_point);
		if (entry->mount_point == NULL) {
			free(entry);
			fclose(fp);
			return -1;
		}
		entry->mount_source = strdup(mount_source);
		if (entry->mount_source == NULL) {
			free(entry);
			free(entry->mount_point);
			fclose(fp);
			return -1;
		}

		count++;
		list_add_tail(&entry->list, mount_head);
	}

	fclose(fp);
	return count;
}

// Called when the process execute
int mount_info_cache_add_if_absent(pid_t pid, u64 mntns_id)
{
	struct mount_info *m = mount_info_cache_lookup(pid, mntns_id);
	if (m == MOUNT_INFO_INVAL) {
		goto err;
	} else if (m == MOUNT_INFO_NULL) {
		// Mount info is not currently available and needs to be rebuilt.
		m = (struct mount_info *)calloc(1, sizeof(*m));
		if (m == NULL) {
			ebpf_warning("calloc() failed with error "
				     "message: \"%s\", and error number: %d.",
				     strerror(errno), errno);
			goto err;
		}

		m->proc_count = 1;
		m->mntns_id = mntns_id;
		m->entry_count = build_mount_info(pid, &m->mount_head);
		if (m->entry_count == -1)
			goto err;

		if (add_mount_info_to_cache(pid, m))
			goto err;
		ebpf_info("Create mount information: pid %d mntns_id %lu entry_count "
			  "%d proc_count %d refcount %d\n",
			  pid, m->mntns_id, m->entry_count, m->proc_count, m->refcount);
	} else {
		// It already exists in the cache; the process count needs to be incremented.
		AO_INC(&m->proc_count);
		AO_DEC(&m->refcount);
	}

	return 0;
err:
	if (!IS_MOUNT_INFO_ERR(m))
		free(m);
	return -1;

}

// Called when the process exits
int mount_info_cache_remove(pid_t pid, u64 mntns_id)
{
	struct mount_info *m = mount_info_cache_lookup(pid, mntns_id);
	if (IS_MOUNT_INFO_ERR(m))
		return -1;

	// No processes are sharing the mount namespace anymore.
	if (AO_SUB_F(&m->proc_count, 1) == 0) {
		if (delete_mount_info_from_cache(pid, m) == 0)
			free_mount_info(m);
		return 0;
	}

	AO_DEC(&m->refcount);
	return 0;
}

/*
 * Replace the longest suffix of str1 (that is a prefix of str2) with str1.
 * Result is written to 'out' with a maximum size of 'out_size'.
 * e.g.:
 *    const char *str1 = "10.33.49.27:/srv/nfs/data"; (mount source)
 *    const char *str2 = "/nfs/data/ddd"; (file path via eBPF)
 *    const char *new_prefix = "/mnt/nfs"; (mount point)
 * target: "10.33.49.27:/srv/nfs/data/ddd"
 */
static int replace_suffix_prefix(const char *str1, const char *str2,
				 const char *new_prefix
				 __attribute__ ((unused)), char *out,
				 size_t out_size)
{
	size_t len1 = strlen(str1);
	size_t len2 = strlen(str2);

	// Try all possible suffixes of str1
	for (size_t i = 0; i < len1; ++i) {
		const char *suffix = str1 + i;
		size_t suffix_len = len1 - i;

		// Check if this suffix matches the prefix of str2
		if (suffix_len <= len2
		    && strncmp(suffix, str2, suffix_len) == 0) {
			// Match found: replace the suffix with new_prefix
			return snprintf(out, out_size, "%s%s", str1,
					str2 + suffix_len);
		}
	}

	// No match found: copy str2 as-is
	return snprintf(out, out_size, "%s", str2);
}

u32 copy_regular_file_data(int pid, void *dst, void *src, int len,
			   const char *mount_point, const char *mount_source,
			   bool is_nfs)
{
	if (len <= 0)
		return 0;

	struct user_io_event_buffer u_event;
	struct __io_event_buffer event;
	memcpy(&event, src, sizeof(event));
	char *buffer = event.filename;
	u32 buffer_len = event.len;
	u32 buf_offset =
	    offsetof(typeof(struct user_io_event_buffer), filename);

	/*
	 * Due to the maximum length limitation of the data, the file
	 * path may be truncated. Here, only the valid length is considered.
	 */
	if (buf_offset + buffer_len > len) {
		buffer_len = len - buf_offset;
	}

	buffer[buffer_len - 1] = '\0';
	int event_len;
	int i, temp_index = 0;
	char temp[buffer_len + 1];
	temp[0] = '\0';

	/*
	 * The path content is in the form "a\0b\0c\0" and needs to
	 * be converted into the directory format "/c/b/a".
	 *
	 * e.g.:
	 *
	 * buffer "comm\019317\0task\032148\0/\0"
	 * convert to "/32148/task/19317/comm"
	 */
	if (buffer_len <= 1)
		goto copy_event;

	char *p;
	for (i = buffer_len - 2; i >= 0; i--) {
		if (i == 0) {
			p = &buffer[0];
		} else {
			if (buffer[i] != '\0')
				continue;
			p = &buffer[i + 1];
		}

		temp_index +=
		    snprintf(temp + temp_index, sizeof(temp) - temp_index,
			     "%s%s", p, (temp_index > 0 && i != 0) ? "/" : "");

	}

copy_event:
	buffer = u_event.filename;
	if (is_nfs)
		temp_index =
		    replace_suffix_prefix(mount_source, temp, mount_point,
					  buffer, sizeof(event.filename));
	else
		temp_index = snprintf(buffer, sizeof(event.filename), "%s%s",
				      mount_point, temp);
	buffer_len = temp_index + 1;
	u_event.bytes_count = event.bytes_count;
	u_event.operation = event.operation;
	u_event.latency = event.latency;
	u_event.offset = event.offset;
	event_len = offsetof(typeof(struct user_io_event_buffer),
			     filename) + buffer_len;
	safe_buf_copy(dst, len, &u_event, event_len);

	return event_len;
}
