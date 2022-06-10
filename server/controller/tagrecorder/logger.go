package tagrecorder

import "fmt"

func dbQueryResourceFailed(resource string, err error) string {
	return fmt.Sprintf("db query %s failed: %v", resource, err)
}
