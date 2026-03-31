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
