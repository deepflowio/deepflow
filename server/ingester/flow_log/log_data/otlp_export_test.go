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

package log_data

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
