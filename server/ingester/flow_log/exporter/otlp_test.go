package exporter

import "testing"

func TestGetSQLSpanNameAndOperation(t *testing.T) {
	cases := []struct {
		sql      string
		expected [2]string
	}{
		{
			sql:      "select * FROM db.users;",
			expected: [2]string{"select db.users", "select"},
		},
		{
			sql:      "INSERT into users (id, name) VALUES (1, 'Alice')",
			expected: [2]string{"INSERT users", "INSERT"},
		},
		{
			sql:      "UPDATE users SET name='Bob' WHERE id=1",
			expected: [2]string{"UPDATE users", "UPDATE"},
		},
		{
			sql:      "CREATE TABLE users(id INT, name TEXT)",
			expected: [2]string{"CREATE users", "CREATE"},
		},
		{
			sql:      "CREATE DATABASE if not exists userdb",
			expected: [2]string{"CREATE userdb", "CREATE"},
		},
		{
			sql:      "ALTER TABLE users ADD COLUMN email TEXT",
			expected: [2]string{"ALTER users", "ALTER"},
		},
		{
			sql:      "DROP TABLE IF EXISTS users",
			expected: [2]string{"DROP users", "DROP"},
		},
		{
			sql:      "",
			expected: [2]string{"unknow", ""},
		},
	}
	for _, c := range cases {
		spanName, operation := getSQLSpanNameAndOperation(c.sql)
		got := [2]string{spanName, operation}
		if got != c.expected {
			t.Errorf("getSQLSpanNameAndOperation(%q) == %q, expected %q", c.sql, got, c.expected)
		}
	}
}
