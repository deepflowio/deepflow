package updater

import (
	"encoding/json"
	"reflect"
	"testing"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

func TestLearnedCloudTagsUpdate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		old, next map[string]string
		changed   bool
	}{
		{"add", nil, map[string]string{"应用编码": "YYZXT202504253457"}, true},
		{"replace", map[string]string{"应用编码": "old"}, map[string]string{"应用编码": "new"}, true},
		{"clear_nil", map[string]string{"应用编码": "old"}, nil, true},
		{"clear_empty", map[string]string{"应用编码": "old"}, map[string]string{}, true},
		{"unchanged", map[string]string{"应用编码": "same"}, map[string]string{"应用编码": "same"}, false},
	} {
		for _, resource := range []string{"vm", "pod_namespace"} {
			t.Run(resource+"/"+tc.name, func(t *testing.T) {
				var updates map[string]interface{}
				var changed bool
				if resource == "vm" {
					_, updates, changed = new(VM).generateUpdateInfo(
						&diffbase.VM{Label: "vm", LearnedCloudTags: tc.old},
						&cloudmodel.VM{Label: "vm", CloudTags: tc.next})
				} else {
					_, updates, changed = new(PodNamespace).generateUpdateInfo(
						&diffbase.PodNamespace{LearnedCloudTags: tc.old},
						&cloudmodel.PodNamespace{CloudTags: tc.next})
				}
				value, exists := updates["learned_cloud_tags"]
				if changed != tc.changed || exists != tc.changed {
					t.Fatalf("changed=%v, tags present=%v, want %v", changed, exists, tc.changed)
				}
				if !tc.changed {
					return
				}
				text, ok := value.(string)
				if !ok {
					t.Fatalf("SQL parameter type = %T, want string", value)
				}
				var got map[string]string
				if err := json.Unmarshal([]byte(text), &got); err != nil {
					t.Fatal(err)
				}
				want := tc.next
				if want == nil {
					want = map[string]string{}
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("tags=%v, want %v", got, want)
				}
			})
		}
	}
}
