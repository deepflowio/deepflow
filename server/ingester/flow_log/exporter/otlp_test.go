package exporter

import "testing"

func TestGetSQLSpanName(t *testing.T) {
	cases := []struct {
		sql      string
		expected string
	}{
		{
			sql:      "select * FROM db.users;",
			expected: "select db.users",
		},
		{
			sql:      "INSERT into users (id, name) VALUES (1, 'Alice')",
			expected: "INSERT users",
		},
		{
			sql:      "UPDATE users SET name='Bob' WHERE id=1",
			expected: "UPDATE users",
		},
		{
			sql:      "CREATE TABLE users(id INT, name TEXT)",
			expected: "CREATE users",
		},
		{
			sql:      "CREATE DATABASE if not exists userdb",
			expected: "CREATE userdb",
		},
		{
			sql:      "ALTER TABLE users ADD COLUMN email TEXT",
			expected: "ALTER users",
		},
		{
			sql:      "DROP TABLE IF EXISTS users",
			expected: "DROP users",
		},
		{
			sql:      "",
			expected: "unknow",
		},
	}
	for _, c := range cases {
		got := getSQLSpanName(c.sql)
		if got != c.expected {
			t.Errorf("getSQLSpanName(%q) == %q, expected %q", c.sql, got, c.expected)
		}
	}
}
