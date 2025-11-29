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

package agent

import (
	"testing"
	"time"

	agentconf "github.com/deepflowio/deepflow/server/agent_config"
	"github.com/deepflowio/deepflow/server/controller/http/service"
	"github.com/stretchr/testify/assert"
)

func TestConfigChangelog_timestampConversion(t *testing.T) {
	// Test Unix timestamp to time.Time conversion
	tests := []struct {
		name         string
		timestamp    int
		expectedTime time.Time
	}{
		{
			name:         "Convert timestamp 1732406400 (2024-11-24 00:00:00 UTC)",
			timestamp:    1732406400,
			expectedTime: time.Date(2024, 11, 24, 0, 0, 0, 0, time.UTC),
		},
		{
			name:         "Convert timestamp 1732492800 (2024-11-25 00:00:00 UTC)",
			timestamp:    1732492800,
			expectedTime: time.Date(2024, 11, 25, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := time.Unix(int64(tt.timestamp), 0).UTC()
			assert.Equal(t, tt.expectedTime, result)
		})
	}
}

func TestConfigChangelog_validateTimeRange(t *testing.T) {
	tests := []struct {
		name        string
		timeStart   int
		timeEnd     int
		shouldError bool
	}{
		{
			name:        "Valid time range",
			timeStart:   1732406400, // 2024-11-24 00:00:00
			timeEnd:     1732492800, // 2024-11-25 00:00:00
			shouldError: false,
		},
		{
			name:        "Invalid time range (start after end)",
			timeStart:   1732492800, // 2024-11-25 00:00:00
			timeEnd:     1732406400, // 2024-11-24 00:00:00
			shouldError: true,
		},
		{
			name:        "Same timestamp",
			timeStart:   1732406400,
			timeEnd:     1732406400,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeStart := time.Unix(int64(tt.timeStart), 0)
			timeEnd := time.Unix(int64(tt.timeEnd), 0)

			isInvalid := timeStart.After(timeEnd)
			assert.Equal(t, tt.shouldError, isInvalid)
		})
	}
}

func TestConfigChangelog_intervalBasedOnTimestampRange(t *testing.T) {
	c := &ConfigChangelog{
		ResourceAccess: &service.ResourceAccess{},
	}

	tests := []struct {
		name             string
		timeStartUnix    int64
		timeEndUnix      int64
		expectedInterval string
	}{
		{
			name:             "1 day range (86400 seconds) should return 1h",
			timeStartUnix:    1732406400, // 2024-11-24 00:00:00
			timeEndUnix:      1732492800, // 2024-11-25 00:00:00
			expectedInterval: "1h",
		},
		{
			name:             "3 days range (259200 seconds) should return 1h",
			timeStartUnix:    1732406400, // 2024-11-24 00:00:00
			timeEndUnix:      1732665600, // 2024-11-27 00:00:00
			expectedInterval: "1h",
		},
		{
			name:             "4 days range (345600 seconds) should return 1d",
			timeStartUnix:    1732406400, // 2024-11-24 00:00:00
			timeEndUnix:      1732752000, // 2024-11-28 00:00:00
			expectedInterval: "1d",
		},
		{
			name:             "7 days range (604800 seconds) should return 1d",
			timeStartUnix:    1731801600, // 2024-11-17 00:00:00
			timeEndUnix:      1732406400, // 2024-11-24 00:00:00
			expectedInterval: "1d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeStart := time.Unix(tt.timeStartUnix, 0)
			timeEnd := time.Unix(tt.timeEndUnix, 0)

			result := c.determineInterval(timeStart, timeEnd)
			assert.Equal(t, tt.expectedInterval, result)
		})
	}
}

func TestConfigChangelog_determineInterval(t *testing.T) {
	c := &ConfigChangelog{
		ResourceAccess: &service.ResourceAccess{},
	}

	tests := []struct {
		name      string
		timeStart time.Time
		timeEnd   time.Time
		expected  string
	}{
		{
			name:      "1 day range should return 1h",
			timeStart: time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC),
			timeEnd:   time.Date(2025, 11, 25, 0, 0, 0, 0, time.UTC),
			expected:  "1h",
		},
		{
			name:      "3 days range should return 1h",
			timeStart: time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC),
			timeEnd:   time.Date(2025, 11, 27, 0, 0, 0, 0, time.UTC),
			expected:  "1h",
		},
		{
			name:      "exactly 3 days should return 1h",
			timeStart: time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC),
			timeEnd:   time.Date(2025, 11, 27, 0, 0, 0, 0, time.UTC),
			expected:  "1h",
		},
		{
			name:      "4 days range should return 1d",
			timeStart: time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC),
			timeEnd:   time.Date(2025, 11, 28, 0, 0, 0, 0, time.UTC),
			expected:  "1d",
		},
		{
			name:      "7 days range should return 1d",
			timeStart: time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC),
			timeEnd:   time.Date(2025, 11, 27, 0, 0, 0, 0, time.UTC),
			expected:  "1d",
		},
		{
			name:      "30 days range should return 1d",
			timeStart: time.Date(2025, 10, 27, 0, 0, 0, 0, time.UTC),
			timeEnd:   time.Date(2025, 11, 26, 0, 0, 0, 0, time.UTC),
			expected:  "1d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.determineInterval(tt.timeStart, tt.timeEnd)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigChangelog_getAggregatedChangelogs_1h(t *testing.T) {
	c := &ConfigChangelog{
		ResourceAccess: &service.ResourceAccess{},
	}

	// Create test data with records in different hours
	baseTime := time.Date(2025, 11, 24, 14, 0, 0, 0, time.UTC)
	timeStart := baseTime
	timeEnd := baseTime.Add(3 * time.Hour) // 14:00 to 17:00 (4 hours)

	changelogs := []agentconf.MetadbAgentGroupConfigurationChangelog{
		{
			ID:        1,
			Lcuuid:    "uuid-1",
			UserID:    1,
			Remarks:   "Change 1",
			CreatedAt: baseTime.Add(10 * time.Minute), // 14:10
		},
		{
			ID:        2,
			Lcuuid:    "uuid-2",
			UserID:    1,
			Remarks:   "Change 2",
			CreatedAt: baseTime.Add(30 * time.Minute), // 14:30
		},
		{
			ID:        3,
			Lcuuid:    "uuid-3",
			UserID:    2,
			Remarks:   "Change 3",
			CreatedAt: baseTime.Add(1*time.Hour + 15*time.Minute), // 15:15
		},
		{
			ID:        4,
			Lcuuid:    "uuid-4",
			UserID:    2,
			Remarks:   "Change 4",
			CreatedAt: baseTime.Add(2*time.Hour + 45*time.Minute), // 16:45
		},
	}

	// Test with 1h interval
	responses := c.getAggregatedChangelogs(changelogs, "1h", timeStart, timeEnd)

	// Should have 4 time slots (14:00, 15:00, 16:00, 17:00) including zero-count slots
	assert.Equal(t, 4, len(responses))

	// Verify time slots and counts
	assert.Equal(t, "2025-11-24 14:00:00", responses[0].TimeSlot)
	assert.Equal(t, 2, responses[0].Count)
	assert.Equal(t, 2, len(responses[0].ChangeLogs))

	assert.Equal(t, "2025-11-24 15:00:00", responses[1].TimeSlot)
	assert.Equal(t, 1, responses[1].Count)
	assert.Equal(t, 1, len(responses[1].ChangeLogs))

	assert.Equal(t, "2025-11-24 16:00:00", responses[2].TimeSlot)
	assert.Equal(t, 1, responses[2].Count)
	assert.Equal(t, 1, len(responses[2].ChangeLogs))

	// 17:00 slot should be empty (zero count)
	assert.Equal(t, "2025-11-24 17:00:00", responses[3].TimeSlot)
	assert.Equal(t, 0, responses[3].Count)
	assert.Equal(t, 0, len(responses[3].ChangeLogs))
}

func TestConfigChangelog_getAggregatedChangelogs_1d(t *testing.T) {
	c := &ConfigChangelog{
		ResourceAccess: &service.ResourceAccess{},
	}

	// Create test data with records in different days
	baseTime := time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)
	timeStart := baseTime
	timeEnd := baseTime.Add(3 * 24 * time.Hour) // Nov 24 to Nov 27 (4 days)

	changelogs := []agentconf.MetadbAgentGroupConfigurationChangelog{
		{
			ID:        1,
			Lcuuid:    "uuid-1",
			UserID:    1,
			Remarks:   "Change 1",
			CreatedAt: baseTime.Add(2 * time.Hour), // Nov 24, 02:00
		},
		{
			ID:        2,
			Lcuuid:    "uuid-2",
			UserID:    1,
			Remarks:   "Change 2",
			CreatedAt: baseTime.Add(14 * time.Hour), // Nov 24, 14:00
		},
		{
			ID:        3,
			Lcuuid:    "uuid-3",
			UserID:    2,
			Remarks:   "Change 3",
			CreatedAt: baseTime.Add(24*time.Hour + 5*time.Hour), // Nov 25, 05:00
		},
		{
			ID:        4,
			Lcuuid:    "uuid-4",
			UserID:    2,
			Remarks:   "Change 4",
			CreatedAt: baseTime.Add(48*time.Hour + 18*time.Hour), // Nov 26, 18:00
		},
		{
			ID:        5,
			Lcuuid:    "uuid-5",
			UserID:    3,
			Remarks:   "Change 5",
			CreatedAt: baseTime.Add(48*time.Hour + 20*time.Hour), // Nov 26, 20:00
		},
	}

	// Test with 1d interval
	responses := c.getAggregatedChangelogs(changelogs, "1d", timeStart, timeEnd)

	// Should have 4 time slots (Nov 24, 25, 26, 27) including zero-count slots
	assert.Equal(t, 4, len(responses))

	// Nov 24 should have 2 records
	assert.Equal(t, "2025-11-24 00:00:00", responses[0].TimeSlot)
	assert.Equal(t, 2, responses[0].Count)
	assert.Equal(t, 2, len(responses[0].ChangeLogs))

	// Nov 25 should have 1 record
	assert.Equal(t, "2025-11-25 00:00:00", responses[1].TimeSlot)
	assert.Equal(t, 1, responses[1].Count)
	assert.Equal(t, 1, len(responses[1].ChangeLogs))

	// Nov 26 should have 2 records
	assert.Equal(t, "2025-11-26 00:00:00", responses[2].TimeSlot)
	assert.Equal(t, 2, responses[2].Count)
	assert.Equal(t, 2, len(responses[2].ChangeLogs))

	// Nov 27 should be empty (zero count)
	assert.Equal(t, "2025-11-27 00:00:00", responses[3].TimeSlot)
	assert.Equal(t, 0, responses[3].Count)
	assert.Equal(t, 0, len(responses[3].ChangeLogs))
}

func TestConfigChangelog_getAggregatedChangelogs_empty(t *testing.T) {
	c := &ConfigChangelog{
		ResourceAccess: &service.ResourceAccess{},
	}

	// Test with empty changelog list
	baseTime := time.Date(2025, 11, 24, 14, 0, 0, 0, time.UTC)
	timeStart := baseTime
	timeEnd := baseTime.Add(2 * time.Hour)
	changelogs := []agentconf.MetadbAgentGroupConfigurationChangelog{}

	responses := c.getAggregatedChangelogs(changelogs, "1h", timeStart, timeEnd)

	// Should return time slots with zero counts (14:00, 15:00, 16:00)
	assert.Equal(t, 3, len(responses))
	assert.Equal(t, 0, responses[0].Count)
	assert.Equal(t, 0, responses[1].Count)
	assert.Equal(t, 0, responses[2].Count)
}

func TestConfigChangelog_getAggregatedChangelogs_singleRecord(t *testing.T) {
	c := &ConfigChangelog{
		ResourceAccess: &service.ResourceAccess{},
	}

	// Test with single record
	baseTime := time.Date(2025, 11, 24, 14, 30, 0, 0, time.UTC)
	timeStart := time.Date(2025, 11, 24, 14, 0, 0, 0, time.UTC)
	timeEnd := time.Date(2025, 11, 24, 14, 0, 0, 0, time.UTC)

	changelogs := []agentconf.MetadbAgentGroupConfigurationChangelog{
		{
			ID:        1,
			Lcuuid:    "uuid-1",
			UserID:    1,
			Remarks:   "Single change",
			CreatedAt: baseTime,
		},
	}

	// Test with 1h interval
	responses := c.getAggregatedChangelogs(changelogs, "1h", timeStart, timeEnd)

	// Should have 1 response
	assert.Equal(t, 1, len(responses))
	assert.Equal(t, "2025-11-24 14:00:00", responses[0].TimeSlot)
	assert.Equal(t, 1, responses[0].Count)
	assert.Equal(t, 1, len(responses[0].ChangeLogs))
	assert.Equal(t, "uuid-1", responses[0].ChangeLogs[0].Lcuuid)

	// Test with 1d interval
	timeStart = time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)
	timeEnd = time.Date(2025, 11, 24, 0, 0, 0, 0, time.UTC)
	responses = c.getAggregatedChangelogs(changelogs, "1d", timeStart, timeEnd)

	// Should have 1 response
	assert.Equal(t, 1, len(responses))
	assert.Equal(t, "2025-11-24 00:00:00", responses[0].TimeSlot)
	assert.Equal(t, 1, responses[0].Count)
	assert.Equal(t, 1, len(responses[0].ChangeLogs))
	assert.Equal(t, "uuid-1", responses[0].ChangeLogs[0].Lcuuid)
}
