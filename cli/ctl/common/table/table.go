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

package table

import (
	"fmt"
	"io"
	"os"
)

const (
	SPACE   = " "
	NEWLINE = "\n"
)

type Table struct {
	headerOut io.Writer
	lineOut   io.Writer
	headers   []string
	lines     [][]string
	maxWidth  map[int]int
	colSize   int
}

func New() *Table {
	return &Table{
		// Show headers when using os.Stderr for grep
		headerOut: os.Stderr,
		lineOut:   os.Stdout,
		headers:   []string{},
		lines:     [][]string{},
		maxWidth:  make(map[int]int),
		colSize:   -1,
	}
}

const indent = 2

func (t *Table) SetHeader(keys []string) {
	t.colSize = len(keys) + indent
	for i, v := range keys {
		t.parseDimension(v, i)
	}
	t.headers = append(t.headers, keys...)
}

func (t *Table) parseDimension(str string, colKey int) {
	maxWidth := 0
	w := displayWidth(str) + indent
	if w > maxWidth {
		maxWidth = w
	}

	// Store the new known maximum width.
	v, ok := t.maxWidth[colKey]
	if !ok || v < maxWidth || v == 0 {
		t.maxWidth[colKey] = maxWidth
	}
}

// AppendBulk uses for Bulk Append
func (t *Table) AppendBulk(rows [][]string) {
	for _, row := range rows {
		t.Append(row)
	}
}

// Append row to table
func (t *Table) Append(row []string) {
	rowSize := len(t.headers)
	if rowSize > t.colSize {
		t.colSize = rowSize
	}

	for i, v := range row {
		// Detect string  width
		t.parseDimension(v, i)
	}
	t.lines = append(t.lines, row)
}

// Render table output
func (t *Table) Render() {
	t.printHeading()
	t.printRows()
}

func (t Table) printRows() {
	for i, lines := range t.lines {
		t.printRow(lines, i)
	}
}

// Print heading information
func (t *Table) printHeading() {
	// Check if headers is available
	if len(t.headers) < 1 {
		return
	}

	for y := 0; y < len(t.maxWidth); y++ {
		width := t.maxWidth[y]
		var h string
		if y < len(t.headers) {
			h = t.headers[y]
		}
		fmt.Fprintf(t.headerOut, "%s%s", padRight(h, SPACE, width), SPACE)
	}
	fmt.Fprint(t.headerOut, NEWLINE)
}

func (t *Table) printRow(columns []string, rowIdx int) {
	for i := 0; i < len(columns); i++ {
		str := columns[i]
		fmt.Fprintf(t.lineOut, "%s%s", padRight(str, SPACE, t.maxWidth[i]), SPACE)
	}
	fmt.Fprint(t.lineOut, NEWLINE)
}
