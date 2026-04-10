package schema

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDBVersionExpectedMatchesHighestMySQLIssue(t *testing.T) {
	issuDir := filepath.Join("rawsql", "mysql", "issu")
	entries, err := os.ReadDir(issuDir)
	if err != nil {
		t.Fatalf("read issu dir failed: %v", err)
	}

	maxVersion := ""
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		if maxVersion == "" || versionGreater(name, maxVersion) {
			maxVersion = name
		}
	}

	if maxVersion == "" {
		t.Fatal("no mysql issue versions found")
	}
	if DB_VERSION_EXPECTED != maxVersion {
		t.Fatalf("DB_VERSION_EXPECTED=%s, want highest issue version %s", DB_VERSION_EXPECTED, maxVersion)
	}
}

func TestMySQLDMLInsert_AIAgentEventDataSourcesShareDefaultRetention(t *testing.T) {
	sqlPath := filepath.Join("rawsql", "mysql", "dml_insert.sql")
	content, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatalf("read dml_insert sql failed: %v", err)
	}
	sql := string(content)

	required := []string{
		"VALUES (27, '事件-文件读写聚合事件', 'event.file_agg_event', 0, 7*24, @lcuuid);",
		"VALUES (28, '事件-文件管理事件', 'event.file_mgmt_event', 0, 7*24, @lcuuid);",
		"VALUES (29, '事件-进程权限事件', 'event.proc_perm_event', 0, 7*24, @lcuuid);",
		"VALUES (30, '事件-进程操作事件', 'event.proc_ops_event', 0, 7*24, @lcuuid);",
	}
	for _, item := range required {
		if !strings.Contains(sql, item) {
			t.Fatalf("missing AI event data source default retention entry: %s", item)
		}
	}
}

func versionGreater(left, right string) bool {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for i := 0; i < len(leftParts) && i < len(rightParts); i++ {
		leftNum, err := strconv.Atoi(leftParts[i])
		if err != nil {
			panic(err)
		}
		rightNum, err := strconv.Atoi(rightParts[i])
		if err != nil {
			panic(err)
		}
		if leftNum == rightNum {
			continue
		}
		return leftNum > rightNum
	}
	return len(leftParts) > len(rightParts)
}
