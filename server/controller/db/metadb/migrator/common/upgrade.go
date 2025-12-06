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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/schema"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/schema/script"
)

func ExecuteCEIssues(dc *DBConfig, curVersion string) error {
	return ExecuteIssues(dc, curVersion, dc.SqlFmt.GetRawSqlDirectory(schema.RAW_SQL_ROOT_DIR))
}

func ExecuteIssues(dc *DBConfig, curVersion string, rawSqlDir string) error {
	issus, err := os.ReadDir(fmt.Sprintf("%s/issu", rawSqlDir))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read %s: %s", rawSqlDir, err.Error()))
		return err
	}
	nextVersions := getAscSortedNextVersions(issus, curVersion)
	log.Info(LogDBName(dc.Config.Database, "%s issues to be executed: %v", rawSqlDir, nextVersions))
	for _, nv := range nextVersions {
		err = executeScript(dc, nv)
		if err != nil {
			return err
		}
		err = executeIssue(dc, nv, rawSqlDir)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeIssue(dc *DBConfig, nextVersion string, rawSqlDir string) error {
	byteSQL, err := os.ReadFile(fmt.Sprintf("%s/issu/%s.sql", rawSqlDir, nextVersion))
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to read sql file (version: %s): %s", nextVersion, err.Error()))
		return err
	}
	if len(byteSQL) == 0 {
		log.Warning(LogDBName(dc.Config.Database, "%s issue with no content (version: %s)", rawSqlDir, nextVersion))
		return nil
	}

	strSQL := fmt.Sprintf("SET @defaultDatabaseName='%s';\n", "deepflow") + string(byteSQL) // TODO: remove hard code
	err = dc.DB.Exec(strSQL).Error
	if err != nil {
		log.Error(LogDBName(dc.Config.Database, "failed to execute %s issue (version: %s): %s", rawSqlDir, nextVersion, err.Error()))
		return err
	}
	log.Info(LogDBName(dc.Config.Database, "executed %s issue (version: %s) successfully", rawSqlDir, nextVersion))
	return nil
}

func executeScript(dc *DBConfig, nextVersion string) error { // TODO ce
	var err error
	switch nextVersion {
	case script.SCRIPT_UPDATE_CLOUD_TAG:
		err = script.ScriptUpdateCloudTags(dc.DB)
	case script.SCRIPT_UPDATE_VM_PODNS_TAG:
		err = script.ScriptUpdateVMPodNSTags(dc.DB)
	case script.SCRIPT_UPGRADE_VTAP_GROUP_CONFIG:
		err = script.UpgradeVTapAgentConfig(dc.DB)
	default:
		err = script.ExecuteScript(dc.DB, nextVersion)
	}
	return err
}

func getAscSortedNextVersions(files []fs.DirEntry, curVersion string) []string {
	vs := []string{}
	for _, f := range files {
		vs = append(vs, trimFilenameExt(f.Name()))
	}
	// asc sort: split version by ".", compare each number from first to end
	sort.Slice(vs, func(i, j int) bool {
		il := strings.Split(vs[i], ".")
		jl := strings.Split(vs[j], ".")
		return !list1GreaterList2(il, jl)
	})

	nvs := []string{}
	cvl := strings.Split(curVersion, ".")
	for _, v := range vs {
		vl := strings.Split(v, ".")
		if list1GreaterList2(vl, cvl) {
			nvs = append(nvs, v)
		}
	}
	return nvs
}

func trimFilenameExt(filename string) string {
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}

func list1GreaterList2(strList1, strList2 []string) bool {
	for i := range strList1 {
		if strList1[i] == strList2[i] {
			continue
		} else {
			in, _ := strconv.Atoi(strList1[i])
			jn, _ := strconv.Atoi(strList2[i])
			return in > jn
		}
	}
	return false
}
