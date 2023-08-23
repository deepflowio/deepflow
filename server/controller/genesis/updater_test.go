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

package genesis

import "testing"

func Test_truncateProcessName(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "greater than 256 characters",
			args: args{
				str: "v7ERxDTfOvwZLd0Jkn7ec0I1W6Mdivfk2-M0QrXeEM_8YF_ZeRpaHOEa990vEwUAdOZWawBh1N5Uxu_ZdyPeZxrCrZWefO2nBqxthO5-RF2VgRTjM5RtQuugt-tDdYybKGQzVzsvGUePtSs--fTgUeyzS0poJ-wsQJXpIAZTAxLj-D94Ao3mz-ChFht4prM0EZ1s7vDOLQzvmr0Ku3EGcL_AO4j0WboyGjxEhstdIAFBk0327vDOLQzvmr0Ku3EGcL_AO4j0Wbo",
			},
			want: "v7ERxDTfOvwZLd0Jkn7ec0I1W6Mdivfk2-M0QrXeEM_8YF_ZeRpaHOEa990vEwUAdOZWawBh1N5Uxu_ZdyPeZxrCrZWefO2nBqxthO5-RF2VgRTjM5RtQuugt-tDdYybKGQzVzsvGUePtSs--fTgUeyzS0poJ-wsQJXpIAZTAxLj-D94Ao3mz-ChFht4prM0EZ1s7vDOLQzvmr0Ku3EGcL_AO4j0WboyGjxEhstdIAFBk0327vDOLQzvmr0Ku3EG",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateProcessName(tt.args.str); got != tt.want {
				t.Errorf("truncateProcessName() = %v, want %v", got, tt.want)
			}
		})
	}
}
