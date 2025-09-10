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

#ifndef DF_USER_MOUNT_H
#define DF_USER_MOUNT_H
/*
 * mount_info_hash_t maps from pid to BCC symbol cache.
 */

#define mount_info_hash_t        clib_bihash_8_8_t
#define mount_info_hash_init     clib_bihash_init_8_8
#define mount_info_hash_kv       clib_bihash_kv_8_8_t
#define print_hash_mount_info    print_bihash_8_8
#define mount_info_hash_search   clib_bihash_search_8_8
#define mount_info_hash_add_del  clib_bihash_add_del_8_8
#define mount_info_hash_free     clib_bihash_free_8_8
#define mount_info_hash_key_value_pair_cb        clib_bihash_foreach_key_value_pair_cb_8_8
#define mount_info_hash_foreach_key_value_pair   clib_bihash_foreach_key_value_pair_8_8

typedef u32 kern_dev_t;
#define DEV_INVALID ((kern_dev_t)-1)

/**
 * Filesystem type categories
 * - FS_TYPE_UNKNOWN = Unknown type
 * - FS_TYPE_REGULAR = Local disk filesystem (ext4, xfs, btrfs, etc.)
 * - FS_TYPE_VIRTUAL = Virtual filesystem (proc, sysfs, tmpfs, etc.)
 * - FS_TYPE_NETWORK = Network filesystem (nfs, cifs, ceph, etc.)
 */
typedef enum {
	FS_TYPE_UNKNOWN = 0,
	FS_TYPE_REGULAR = 1,
	FS_TYPE_VIRTUAL = 2,
	FS_TYPE_NETWORK = 3
} fs_type_t;

/// Mapping from filesystem name to type
typedef struct {
	const char *name;
	fs_type_t type;
} fs_map_t;

/**
 * struct mount_entry - Represents a mount point within a mount namespace
 * @list:         Linked list node for chaining multiple mount entries
 * @mount_id:	  The unique mount point ID assigned by the kernel.
 * @s_dev:        Device ID (from stat.st_dev), typically encoded as major:minor
 * @is_nfs:       True if the mount source is a network file system (e.g., NFS)
 * @mount_point:  Absolute path of the mount point (e.g., "/mnt/data")
 * @mount_source: Source of the mount (e.g., "/dev/sda1" or "host:/export")
 */
struct mount_entry {
	struct list_head list;
	int mount_id;
	kern_dev_t s_dev;
	fs_type_t file_type;
	char *mount_point;
	char *mount_source;
};

/**
 * struct mount_info - Stores parsed mount namespace metadata
 * @mount_head:   Linked list node for chaining mount_info structures
 * @refcount:     Reference count indicating how many references exist to this structure
 * @proc_count:   Number of processes sharing this mount namespace
 * @mntns_id:     Mount namespace ID (typically from stat.st_dev or nsfs inode)
 * @bytes_count:  How many bytes does the mount information occupy in total?
 * @file_hash:    Hash of the /proc/<create_pid>/mountinfo file, used to detect changes
 * @entry_count:  Number of mount entries associated with this namespace
 */
struct mount_info {
	struct list_head mount_head;
	int refcount;
	int proc_count;
	u64 mntns_id;
	u32 bytes_count;
	u32 file_hash;
	int entry_count;
};

struct mount_cache_kvp {
	struct {
		u64 mntns_id;
	} k;

	struct {
		u64 mount_info_p;
	} v;
};

/**
 * @brief Initialize the mount info cache.
 *
 * @param[in] name  A name label for logging or internal hash structure
 * @return 0 on success, -1 on failure
 */
int mount_info_cache_init(const char *name);

/**
 * @brief Retrieve mount namespace ID for the given PID.
 *
 * @param[in]  pid        Target process PID
 * @param[out] mntns_id   Pointer to store mount namespace inode
 * @return 0 on success, -1 on failure
 */
int get_mount_ns_id(pid_t pid, u64 * mntns_id);

/**
 * @brief Lookup mount info from cache using PID or mount ns ID.
 *
 * @param[in] pid        Process ID (can be 0 if mntns_id is specified)
 * @param[in] mntns_id   Mount namespace ID (0 means lookup by PID)
 * @return pointer to mount_info on hit, MOUNT_INFO_NULL or MOUNT_INFO_INVAL on miss/failure
 */
struct mount_info *mount_info_cache_lookup(pid_t pid, u64 mntns_id);

/**
 * @brief Add mount info to cache if not already present.
 *
 * Called when a process starts. If the mount info does not exist in cache,
 * it will be parsed and added. If it exists, increases process count.
 *
 * @param[in] pid        Process ID
 * @param[in] mntns_id   Mount namespace ID
 * @return 0 on success, -1 on failure
 */
int mount_info_cache_add_if_absent(pid_t pid, u64 mntns_id);

/**
 * @brief Remove reference to mount info in cache on process exit.
 *
 * Decreases process count. If count reaches 0, the mount info is deleted.
 *
 * @param[in] pid        Process ID
 * @param[in] mntns_id   Mount namespace ID
 * @return 0 on success, -1 on failure
 */
int mount_info_cache_remove(pid_t pid, u64 mntns_id);

/**
 * @brief Find the mount path and source device for a given device ID in a namespace.
 *
 * @param[in]  pid            Process ID
 * @param[in]  mnt_id	      Mount ID
 * @param[in]  mntns_id       Mount namespace ID
 * @param[in]  s_dev          Device ID (major:minor encoded)
 * @param[out] mount_path     Output buffer for mount point path
 * @param[out] mount_source   Output buffer for mount source (e.g., device or NFS path)
 * @param[in]  mount_size     Size of output buffers
 * @param[out] file_type      File type
 */
void get_mount_info(pid_t pid, int mnt_id, u32 mntns_id,
		    kern_dev_t s_dev, char *mount_path,
		    char *mount_source, int mount_size, fs_type_t * file_type);

/**
 * @brief Copy and transform event data containing file paths from eBPF trace.
 *
 * For NFS mounts, replaces path prefix using mount source; otherwise uses mount point.
 *
 * @param[in]  pid           Process ID
 * @param[out] dst           Destination buffer
 * @param[in]  src           Source buffer (raw eBPF event)
 * @param[in]  len           Length of destination buffer
 * @param[in]  mount_point   Mount point path
 * @param[in]  mount_source  Mount source path
 * @param[in]  file_type     File type (FS_TYPE_REGULAR, FS_TYPE_VIRTUAL, FS_TYPE_NETWORK)
 * @return Number of bytes written to dst
 */
uint32_t copy_file_metrics(int pid, void *dst, void *src, int len,
			   const char *mount_point,
			   const char *mount_source, fs_type_t file_type);
/**
 * @brief Check for changes in the host root mount namespace's mount information.
 *
 * This function periodically computes the hash of `/proc/1/mountinfo` to detect
 * changes in the host root's mount namespace. If a change is detected, the old
 * cached mount information is removed and the updated data is re-added to the cache.
 *
 * It uses PID 1 (usually the init process) as a reference for the host root mount namespace.
 *
 * @param output_log       Should a log be output?
 *
 * @note This function assumes `host_root_mountinfo_hash` and `host_root_mntns_id`
 *       are globally defined and initialized appropriately.
 */
void check_root_mount_info(bool output_log);

/**
 * create_proc_mount_info - Create and cache mount information for a process
 * @pid:        The process ID whose mountinfo should be parsed
 * @mntns_id:   The mount namespace ID associated with the process
 *
 * This function creates a new mount_info structure for the given process ID,
 * parses the mount entries under /proc/[pid]/mountinfo, and stores the result
 * into an internal cache.
 *
 * Return: struct mount_info address on success, NULL on failure.
 */
struct mount_info *create_proc_mount_info(pid_t pid, u64 mntns_id);

/**
 * check_and_cleanup_mount_info - Check if a mount_info entry is stale and remove it if needed
 * @pid:        PID of the process associated with the mount namespace
 * @mntns_id:   Mount namespace identifier (typically from nsfs or stat)
 *
 * This function searches for the mount_info entry associated with the given
 * mount namespace. It verifies whether the cached entry is outdated by comparing
 * the current hash of /proc/[pid]/mountinfo with the stored file_hash.
 * If the entry is determined to be stale (e.g., the file has changed or is no longer used),
 * it is removed from the cache and cleaned up.
 *
 * This helps prevent stale mount namespace information from persisting in memory.
 */
void check_and_cleanup_mount_info(pid_t pid, u64 mntns_id);

/**
 * collect_mount_info_stats - Traverse and optionally log statistics about mount info cache
 * @output_log: If true, logs the number of checked entries in the mount info cache
 *
 * This function iterates through all key-value pairs in the mount_info_hash cache,
 * using a callback to check and optionally update statistics such as the number of entries.
 * It can optionally output a log message summarizing the number of entries examined.
 * 
 * After traversal, it resets the global variable `mnt_bytes` to 0, possibly preparing
 * for future accumulation of mount memory size statistics.
 */
void collect_mount_info_stats(bool output_log);

/**
 * fs_type_to_string - Convert a filesystem type enum to a human-readable string.
 *
 * @type: The filesystem type, one of FS_TYPE_UNKNOWN, FS_TYPE_REGULAR, 
 *        FS_TYPE_VIRTUAL, or FS_TYPE_NETWORK.
 *
 * Returns:
 *   A constant string representing the filesystem type:
 *   - "regular" for FS_TYPE_REGULAR
 *   - "virtual" for FS_TYPE_VIRTUAL
 *   - "network" for FS_TYPE_NETWORK
 *   - "unknown" for FS_TYPE_UNKNOWN or any unrecognized value
 *
 * This function is safe to use for logging, debugging, or displaying
 * filesystem type information in a human-readable format.
 */
const char *fs_type_to_string(fs_type_t type);

/**
 * Retrieve the mount ID of a given file descriptor from /proc/<pid>/fdinfo/<fd>.
 *
 * This function reads the "mnt_id" field from the corresponding fdinfo file
 * in the /proc filesystem. It provides a simple and direct way to obtain the
 * mount ID without parsing /proc/<pid>/mountinfo or using name_to_handle_at().
 *
 * @param pid  Target process ID.
 * @param fd   File descriptor within the target process.
 * @return     On success: non-negative mount ID.
 *             On failure: -1 is returned, and errno is set accordingly.
 */
int get_mount_id(pid_t pid, int fd);

int mount_offset_infer(void);
#endif /* DF_USER_MOUNT_H */
