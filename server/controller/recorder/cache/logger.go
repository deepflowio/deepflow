package cache

import (
	"fmt"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("recorder.cache")

func dbQueryResourceFailed(resource string, err error) string {
	return fmt.Sprintf("db query %s failed: %v", resource, err)
}

func dbResourceByLcuuidNotFound(resource, lcuuid string) string {
	return fmt.Sprintf("db %s (lcuuid: %s) not found", resource, lcuuid)
}

func dbResourceByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("db %s (id: %d) not found", resource, id)
}

func cacheLcuuidByIDNotFound(resource string, id int) string {
	return fmt.Sprintf("cache %s lcuuid (id: %d) not found", resource, id)
}

func cacheIDByLcuuidNotFound(resource string, lcuuid string) string {
	return fmt.Sprintf("cache %s id (lcuuid: %s) not found", resource, lcuuid)
}

func addDiffBase(resource string, detail interface{}) string {
	return fmt.Sprintf("cache diff base add %s (detail: %+v) success", resource, detail)
}

func updateDiffBase(resource string, detail interface{}) string {
	return fmt.Sprintf("cache diff base update %s (detail: %+v) success", resource, detail)
}

func deleteDiffBase(resource, lcuuid string) string {
	return fmt.Sprintf("cache diff base delete %s (lcuuid: %s) success", resource, lcuuid)
}

func refreshResource(resource string) string {
	return fmt.Sprintf("refresh %s", resource)
}
