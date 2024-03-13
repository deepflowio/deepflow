package translate

import (
	"embed"
	"fmt"
	"strings"
)

// go:embed ../../enum/*.en
var embeddedFiles embed.FS

func load() error {
	files, err := embeddedFiles.ReadDir("enum")
	if err != nil {
		return fmt.Errorf("error reading directory:", err)
	}

	for _, file := range files {
		filename := file.Name()
		if strings.HasSuffix(filename, ".en") {
			content, err := embeddedFiles.ReadFile("data/" + filename)
			if err != nil {
				fmt.Printf("error reading file %s: %v\n", filename, err)
				continue
			}
			parseContent()
		}
	}
	return nil
}
