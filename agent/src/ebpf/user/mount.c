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
// Stores the mount namespace ID of the host root
static u64 host_root_mntns_id = 0;

// Stores the hash value of the host root's mountinfo data
static u32 host_root_mountinfo_hash = 0;

static bool inline enable_mount_info_cache(void)
{
	return (mount_info_hash.buckets != NULL);
}

static int hash_mountinfo_file(pid_t pid, u32 * out_hash)
{
	if (!out_hash)
		return -1;

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);

	FILE *fp = fopen(path, "rb");
	if (!fp) {
		return -1;
	}

	const u32 seed = 0;
	u32 hash = seed;

	unsigned char buffer[4096];
	size_t read_len;

	while ((read_len = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
		hash = murmurhash(buffer, read_len, hash);
	}

	if (ferror(fp)) {
		fclose(fp);
		return -1;
	}

	fclose(fp);

	*out_hash = hash;
	return 0;
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
		ebpf_debug("The stat() call failed with error "
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

void get_mount_info(pid_t pid, u64 * mntns_id, kern_dev_t s_dev,
		    char *mount_path, char *mount_source,
		    int mount_size, fs_type_t * file_type)
{
	struct list_head *p, *n;
	struct mount_entry *e;
	struct mount_info *m = mount_info_cache_lookup(pid, *mntns_id);
	if (m == MOUNT_INFO_INVAL)
		return;

	if (m == MOUNT_INFO_NULL) {
		get_mount_ns_id(pid, mntns_id);
		m = create_proc_mount_info(pid, *mntns_id);
		if (m == NULL)
			return;
		AO_INC(&m->refcount);
	}

	if (!m->mount_head.next) {
		AO_DEC(&m->refcount);
		return;
	}

	list_for_each_safe(p, n, &m->mount_head) {
		e = container_of(p, struct mount_entry, list);
		if (e && e->s_dev == s_dev) {
			fast_strncat_trunc(e->mount_point, "", mount_path,
					   mount_size);
			fast_strncat_trunc(e->mount_source, "", mount_source,
					   mount_size);
			*file_type = e->file_type;
			break;
		}
	}

	AO_DEC(&m->refcount);
}

int mount_info_cache_init(const char *name)
{
	// Get the mount namespace ID of the host root.
	get_mount_ns_id(1, &host_root_mntns_id);
	// Get host root's mountinfo data
	hash_mountinfo_file(1, &host_root_mountinfo_hash);
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
	while (AO_GET(&m->refcount) > 1)
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
		  " proc_count %d refcount %d bytes_count %u bytes.\n",
		  m->mntns_id, m->entry_count, m->proc_count,
		  m->refcount, m->bytes_count);
	free(m);
}

static int delete_mount_info_from_cache(pid_t pid, struct mount_info *m)
{
	if (m->mntns_id == host_root_mntns_id)
		return -1;
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
	    (h, (mount_info_hash_kv *) & kv,
	     2 /* is_add = 2, Add but do not overwrite?  */ )) {
		ebpf_warning("failed.(pid %d, mntns_id %lu)\n", pid,
			     m->mntns_id);
		return -1;
	}

	return 0;
}

/// Static mapping table, common filesystems placed first for faster matching
static const fs_map_t fs_map[] = {
	// Most common filesystems first
	{"ext4", FS_TYPE_REGULAR},
	{"xfs", FS_TYPE_REGULAR},
	{"proc", FS_TYPE_VIRTUAL},
	{"sysfs", FS_TYPE_VIRTUAL},
	{"nfs", FS_TYPE_NETWORK},
	{"nfs4", FS_TYPE_NETWORK},

	// Other local filesystems
	{"ext2", FS_TYPE_REGULAR},
	{"ext3", FS_TYPE_REGULAR},
	{"btrfs", FS_TYPE_REGULAR},
	{"f2fs", FS_TYPE_REGULAR},
	{"zfs", FS_TYPE_REGULAR},

	// Other virtual filesystems
	{"devtmpfs", FS_TYPE_VIRTUAL},
	{"tmpfs", FS_TYPE_VIRTUAL},
	{"cgroup", FS_TYPE_VIRTUAL},
	{"cgroup2", FS_TYPE_VIRTUAL},
	{"mqueue", FS_TYPE_VIRTUAL},
	{"debugfs", FS_TYPE_VIRTUAL},
	{"tracefs", FS_TYPE_VIRTUAL},
	{"securityfs", FS_TYPE_VIRTUAL},
	{"configfs", FS_TYPE_VIRTUAL},
	{"pstore", FS_TYPE_VIRTUAL},
	{"overlay", FS_TYPE_VIRTUAL},

	// Other network filesystems
	{"cifs", FS_TYPE_NETWORK},
	{"smb3", FS_TYPE_NETWORK},
	{"ceph", FS_TYPE_NETWORK},
	{"glusterfs", FS_TYPE_NETWORK},
	{"9p", FS_TYPE_NETWORK},

	{NULL, FS_TYPE_UNKNOWN}	// Sentinel
};

const char *fs_type_to_string(fs_type_t type)
{
	switch (type) {
	case FS_TYPE_REGULAR:
		return "regular";
	case FS_TYPE_VIRTUAL:
		return "virtual";
	case FS_TYPE_NETWORK:
		return "network";
	case FS_TYPE_UNKNOWN:
	default:
		return "unknown";
	}
}

/**
 * Determine filesystem category from fstype (string from /proc/<pid>/mountinfo)
 * @param fstype - filesystem type string
 * @return fs_type_t - enum category (LOCAL / VIRTUAL / NETWORK / UNKNOWN)
 */
static fs_type_t get_fs_type(const char *fstype)
{
	if (!fstype)
		return FS_TYPE_UNKNOWN;

	if (strncmp(fstype, "fuse", 4) == 0)
		return FS_TYPE_VIRTUAL;

	for (int i = 0; fs_map[i].name != NULL; i++) {
		if (strcmp(fstype, fs_map[i].name) == 0) {
			return fs_map[i].type;
		}
	}
	return FS_TYPE_UNKNOWN;
}

static int build_mount_info(pid_t pid, struct list_head *mount_head,
			    u32 * bytes_count)
{
	char path[64];
	int count = 0;
	*bytes_count = 0;
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

		kern_dev_t s_dev = ((major & 0xfff) << 20) | (minor & 0xfffff);
		if (has_mount_entry(mount_head, s_dev))
			continue;
		struct mount_entry *entry =
		    calloc(1, sizeof(struct mount_entry));
		if (entry == NULL) {
			ebpf_warning("calloc failed with %s(%d)\n",
				     strerror(errno), errno);
			goto exit;
		}

		entry->s_dev = s_dev;
		entry->file_type = get_fs_type(fs_type);
		entry->mount_point = strdup(mount_point);
		if (entry->mount_point == NULL) {
			free(entry);
			goto exit;
		}
		entry->mount_source = strdup(mount_source);
		if (entry->mount_source == NULL) {
			free(entry);
			free(entry->mount_point);
			goto exit;
		}

		count++;
		*bytes_count +=
		    (strlen(entry->mount_point) + strlen(entry->mount_source) +
		     2);
		list_add_tail(&entry->list, mount_head);
	}

exit:
	fclose(fp);
	if (*bytes_count > 0 && count > 0)
		*bytes_count += (count * sizeof(struct mount_entry));
	return count;
}

struct mount_info *create_proc_mount_info(pid_t pid, u64 mntns_id)
{
	struct mount_info *m;
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
	m->refcount = 0;
	m->entry_count = build_mount_info(pid, &m->mount_head, &m->bytes_count);
	if (m->entry_count == -1 || m->entry_count == 0)
		goto err;

	m->bytes_count += sizeof(*m);
	hash_mountinfo_file(pid, &m->file_hash);
	if (add_mount_info_to_cache(pid, m))
		goto err;

	ebpf_info
	    ("Create mount information: pid %d mntns_id %lu entry_count "
	     "%d proc_count %d refcount %d bytes_count %u bytes\n",
	     pid, m->mntns_id, m->entry_count, m->proc_count,
	     m->refcount, m->bytes_count);

	return m;
err:
	if (m)
		free_mount_info(m);

	return NULL;
}

// Called when the process execute
int mount_info_cache_add_if_absent(pid_t pid, u64 mntns_id)
{
	struct mount_info *m = mount_info_cache_lookup(pid, mntns_id);
	if (m == MOUNT_INFO_INVAL) {
		return -1;
	} else if (m == MOUNT_INFO_NULL) {
		if (create_proc_mount_info(pid, mntns_id) == NULL)
			return -1;
	} else {
		// It already exists in the cache; the process count needs to be incremented.
		AO_INC(&m->proc_count);
		AO_DEC(&m->refcount);
	}

	return 0;
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
		else
			AO_DEC(&m->refcount);

		return 0;
	}

	AO_DEC(&m->refcount);
	return 0;
}

static u64 mnt_bytes;
static int check_mount_kvp_cb(mount_info_hash_kv * kvp, void *ctx)
{
	struct mount_cache_kvp *kv = (struct mount_cache_kvp *)kvp;
	struct mount_info *p = NULL;
	if (kv->v.mount_info_p) {
		p = (struct mount_info *)kv->v.mount_info_p;
		AO_INC(&p->refcount);
		mnt_bytes += p->bytes_count;
		AO_DEC(&p->refcount);
		ebpf_debug("mount info file_hash %u %u mntns_id %lu"
			   " proc_count %d refcount %d entry_count %d bytes_count %u bytes.\n",
			   p->file_hash, p->mntns_id, p->proc_count,
			   p->refcount, p->entry_count, p->bytes_count);
	}

	(*(u64 *) ctx)++;
	return BIHASH_WALK_CONTINUE;
}

void collect_mount_info_stats(bool output_log)
{
	u64 elems_count = 0;
	mount_info_hash_t *h = &mount_info_hash;
	mount_info_hash_foreach_key_value_pair(h,
					       check_mount_kvp_cb,
					       (void *)&elems_count);
	if (output_log)
		ebpf_info("Checked %d entries in the mount info cache, "
			  "occupies %lu bytes of memory.\n",
			  elems_count, mnt_bytes);
	mnt_bytes = 0;
}

void check_and_cleanup_mount_info(pid_t pid, u64 mntns_id)
{
	struct mount_info *m = mount_info_cache_lookup(pid, mntns_id);
	if (IS_MOUNT_INFO_ERR(m))
		return;

	u32 new_hash = 0;
	if (hash_mountinfo_file(pid, &new_hash)) {
		AO_DEC(&m->refcount);
		return;
	}

	if (new_hash != m->file_hash) {
		if (delete_mount_info_from_cache(pid, m) == 0)
			free_mount_info(m);
		else
			AO_DEC(&m->refcount);

		return;
	}

	AO_DEC(&m->refcount);
}

// Periodically check whether the host node's mount information has changed.
void check_root_mount_info(bool output_log)
{
	u32 new_hash = 0;
	hash_mountinfo_file(1, &new_hash);
	if (new_hash != 0 && new_hash != host_root_mountinfo_hash) {
		u64 tmp_mntns_id = host_root_mntns_id;
		struct mount_info *m =
		    mount_info_cache_lookup(1, host_root_mntns_id);
		if (!IS_MOUNT_INFO_ERR(m)) {
			// Ensure that the root mount point can be cleaned up.
			host_root_mntns_id = 0;
			if (delete_mount_info_from_cache(1, m) == 0)
				free_mount_info(m);
			else
				AO_DEC(&m->refcount);
			host_root_mntns_id = tmp_mntns_id;
		}

		ebpf_info
		    ("The mount information of the host root namespace has changed; updating the mount info.\n");
		host_root_mountinfo_hash = new_hash;
	}
}

/*
 * Replace the longest suffix of str1 (that is a prefix of str2) with str1.
 * Result is written to 'out' with a maximum size of 'out_size'.
 * e.g.:
 *    const char *str1 = "/mnt/nfs"; (mount point)
 *    const char *str2 = "/nfs/data/"; (file dir via eBPF)
 * target: "/mnt/nfs/data/"
 */
static int replace_suffix_prefix(const char *str1, const char *str2, char *out,
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
			// Match found: replace the suffix with str2
			return fast_strncat_trunc(str1, str2 + suffix_len, out,
						  out_size);
		}
	}

	// No match found: copy str1 + str2
	return fast_strncat_trunc(str1, str2, out, out_size);
}

u32 copy_file_metrics(int pid, void *dst, void *src, int len,
		      const char *mount_point, const char *mount_source,
		      fs_type_t file_type)
{
	if (len <= 0)
		return 0;

	struct user_io_event_buffer *u_event;
	struct __io_event_buffer *event = (struct __io_event_buffer *)src;
	char *buffer = event->filename;
	u32 buffer_len = event->len;
	u32 buf_offset =
	    offsetof(typeof(struct user_io_event_buffer), filename);

	/*
	 * Due to the maximum length limitation of the data, the file
	 * path may be truncated. Here, only the valid length is considered.
	 */
	if (buf_offset + buffer_len > len) {
		buffer_len = len - buf_offset;
	}

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
	int copy_len;
	for (i = buffer_len - 2; i > 0; i--) {
		if (buffer[i] != '\0')
			continue;
		p = &buffer[i + 1];

		copy_len =
		    fast_strncat_trunc(p, (temp_index > 0 && i != 0) ? "/" : "",
				       temp + temp_index,
				       sizeof(temp) - temp_index);
		temp_index += copy_len;
	}

copy_event:
	u_event = (struct user_io_event_buffer *)dst;
	buffer = u_event->file_dir;
	if (file_type == FS_TYPE_NETWORK) {
		temp_index =
		    replace_suffix_prefix(mount_point, temp, buffer,
					  sizeof(u_event->file_dir));
	} else {
		const char *point = mount_point;
		// Ensure no duplicate slashes appear in the path (e.g., //tmp/filename)
		if (mount_point[0] == '/' && mount_point[1] == '\0')
			point = "";
		temp_index =
		    fast_strncat_trunc(point, temp, buffer,
				       sizeof(u_event->file_dir));
	}

	u_event->bytes_count = event->bytes_count;
	u_event->operation = event->operation;
	u_event->latency = event->latency;
	u_event->offset = event->offset;
	u_event->file_type = file_type;
	strcpy_s_inline(u_event->mount_source, sizeof(u_event->mount_source),
			mount_source, strlen(mount_source));
	strcpy_s_inline(u_event->mount_point, sizeof(u_event->mount_point),
			mount_point, strlen(mount_point));
	strcpy_s_inline(u_event->filename, sizeof(u_event->filename),
			event->filename, strlen(event->filename));
	return sizeof(*u_event);
}
