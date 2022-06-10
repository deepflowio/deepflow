package updater

import (
	"fmt"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("recorder.updater")

func resourceAForResourceBNotFound(resourceA, lcuuidA, resourceB, lcuuidB string) string {
	return fmt.Sprintf("%s (lcuuid: %s) for %s (lcuuid: %s) not found", resourceA, lcuuidA, resourceB, lcuuidB)
}
