/**
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

package model

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zlib"
)

// AI code
// AutoCompressedBytes automatically compresses data when writing to database
// and decompresses when reading. In-memory representation is always decompressed.
// This type implements sql.Scanner and driver.Valuer interfaces for transparent
// compression/decompression with database operations.
type AutoCompressedBytes []byte

// Scan decompresses value from database into autoCompressedBytes.
// Implements sql.Scanner interface for reading from database.
func (a *AutoCompressedBytes) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}

	compressedData, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("failed to scan autoCompressedBytes value:", value))
	}

	// Handle empty data
	if len(compressedData) == 0 {
		*a = []byte{}
		return nil
	}

	// Decompress using zlib
	var b bytes.Buffer
	b.Write(compressedData)
	r, err := zlib.NewReader(&b)
	if err != nil {
		return fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer r.Close()

	decompressedData, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to decompress data: %w", err)
	}

	*a = decompressedData
	return nil
}

// Value compresses autoCompressedBytes for storage in database.
// Implements driver.Valuer interface for writing to database.
// Returns []byte to ensure compatibility with BLOB/BINARY columns.
func (a AutoCompressedBytes) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}

	// Handle empty data
	if len(a) == 0 {
		return []byte{}, nil
	}

	// Compress using zlib
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, err := w.Write(a)
	if err != nil {
		return nil, fmt.Errorf("failed to write compressed data: %w", err)
	}
	if err = w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zlib writer: %w", err)
	}

	return b.Bytes(), nil
}
