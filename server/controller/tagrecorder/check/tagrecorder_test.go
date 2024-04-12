/*
 * Copyright (c) 2023 Yunshan Networks
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

package tagrecorder

import (
	"testing"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func Test_genH64(t *testing.T) {
	tests := []struct {
		name        string
		wantOldHash uint64
		wantNewHash uint64
		wantErr     bool
		testFunc    func(t *testing.T) (oldHash, newHash uint64, err error)
	}{
		{
			name:        "ch_az normal",
			wantOldHash: 11011604902492736609,
			wantNewHash: 11011604902492736609,
			wantErr:     false,
			testFunc: func(t *testing.T) (oldHash uint64, newHash uint64, err error) {
				oldItems := []mysql.ChAZ{
					{ID: 1, Name: "test-1"},
				}
				newItems := []mysql.ChAZ{
					{ID: 1, Name: "test-1"},
				}

				oldHash, newHash, err = genH64[mysql.ChAZ](oldItems, newItems)
				return
			},
		},
		{
			name:        "ch_az old item without iconid",
			wantOldHash: 11011604902492736609,
			wantNewHash: 10481254369259614302,
			wantErr:     false,
			testFunc: func(t *testing.T) (oldHash uint64, newHash uint64, err error) {
				oldItems := []mysql.ChAZ{
					{ID: 1, Name: "test-1"},
				}
				newItems := []mysql.ChAZ{
					{ID: 1, Name: "test-1", IconID: 1},
				}

				oldHash, newHash, err = genH64[mysql.ChAZ](oldItems, newItems)
				return
			},
		},
		{
			name:        "ch_az new item out of order",
			wantOldHash: 10836103067972662261,
			wantNewHash: 10836103067972662261,
			wantErr:     false,
			testFunc: func(t *testing.T) (oldHash uint64, newHash uint64, err error) {
				oldItems := []mysql.ChAZ{
					{ID: 1, Name: "test-1", IconID: 1},
					{ID: 2, Name: "test-2", IconID: 2},
					{ID: 3, Name: "test-3", IconID: 3},
				}
				newItems := []mysql.ChAZ{
					{ID: 2, Name: "test-2", IconID: 2},
					{ID: 1, Name: "test-1", IconID: 1},
					{ID: 3, Name: "test-3", IconID: 3},
				}

				oldHash, newHash, err = genH64[mysql.ChAZ](oldItems, newItems)
				return
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOldHash, gotNewHash, err := tt.testFunc(t)
			if (err != nil) != tt.wantErr {
				t.Errorf("genH64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOldHash != tt.wantOldHash {
				t.Errorf("genH64() gotOldHash = %v, want %v", gotOldHash, tt.wantOldHash)
			}
			if gotNewHash != tt.wantNewHash {
				t.Errorf("genH64() gotNewHash = %v, want %v", gotNewHash, tt.wantNewHash)
			}
		})
	}
}
