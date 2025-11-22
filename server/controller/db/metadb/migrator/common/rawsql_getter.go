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

package common

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AI code
// GetSortedSQLFiles returns the .sql files in the target directory sorted by these rules:
// 1. Files starting with ddl_ come before files starting with dml_.
// 2. Within ddl_ files: those containing create_table run first, those containing create_trigger run last, any other ddl_* files are in between.
// 3. If defaultDB is true, only files starting with default_db_ are considered; that prefix is stripped for applying the same sorting rules.
func GetSortedSQLFiles(parentDir string, defaultDB bool) []string {
	entries, err := os.ReadDir(parentDir)
	if err != nil {
		return nil
	}

	type fileItem struct {
		name      string // original filename
		sortGroup int    // for ordering
		sortName  string // secondary alphabetical within group
	}

	var items []fileItem
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fname := e.Name()
		if !strings.HasSuffix(fname, ".sql") {
			continue
		}

		if defaultDB {
			if !strings.HasPrefix(fname, "default_db_") {
				continue
			}
		} else {
			if strings.HasPrefix(fname, "default_db_") { // skip default-only files
				continue
			}
		}

		// Classification name (strip default_db_ prefix for ordering if needed)
		comp := fname
		if defaultDB {
			comp = strings.TrimPrefix(comp, "default_db_")
		}

		// Determine sort group
		// 0: ddl_ + contains create_table
		// 1: other ddl_
		// 2: ddl_ + contains create_trigger
		// 3: dml_
		// Unrecognized prefixes go after known ones (group 4)
		var group int
		switch {
		case strings.HasPrefix(comp, "ddl_") && strings.Contains(comp, "create_table"):
			group = 0
		case strings.HasPrefix(comp, "ddl_") && strings.Contains(comp, "create_trigger"):
			group = 2
		case strings.HasPrefix(comp, "ddl_"):
			group = 1
		case strings.HasPrefix(comp, "dml_"):
			group = 3
		default:
			group = 4
		}

		items = append(items, fileItem{name: fname, sortGroup: group, sortName: comp})
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].sortGroup != items[j].sortGroup {
			return items[i].sortGroup < items[j].sortGroup
		}
		return items[i].sortName < items[j].sortName
	})

	results := make([]string, 0, len(items))
	for _, it := range items {
		results = append(results, filepath.Join(parentDir, it.name))
	}
	return results
}

// GetDBVersionDDLFile returns the *_db_version.sql file path in the rawSqlDir.
func GetDBVersionDDLFile(rawSqlDir string) string {
	for _, f := range GetSortedSQLFiles(rawSqlDir, false) {
		if strings.Contains(f, "_db_version") {
			return f
		}
	}
	return ""
}
