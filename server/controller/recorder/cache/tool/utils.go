package tool

import "regexp"

func extractExecFileFromCmd(commandLine string) string {
	// Regexes to extract executable files from command lines for different languages.
	// They support version numbers in commands (e.g., java8, python3.9),
	// handle various command-line arguments, and extract full file paths (absolute or relative)
	// with or without file extensions.

	// Java: First try to match -jar pattern
	javaJarRe := regexp.MustCompile(`\bjava[\d\.-]*\b(?:.*?)?\s+-jar\s+([^\s]+)`)
	if matches := javaJarRe.FindStringSubmatch(commandLine); len(matches) > 1 {
		return matches[1]
	}

	// Python: Match -m module pattern
	pythonModuleRe := regexp.MustCompile(`\bpython[\d\.-]*\b(?:.*?)?\s+-m\s+([^\s]+)`)
	if matches := pythonModuleRe.FindStringSubmatch(commandLine); len(matches) > 1 {
		return matches[1]
	}

	// Java (without -jar), Node.js, and Python: Match first non-option argument
	generalRe := regexp.MustCompile(`\b(java|node|python)[\d\.-]*\b(?:.*?)?\s+([^\s-]\S*)`)
	if matches := generalRe.FindStringSubmatch(commandLine); len(matches) > 2 {
		return matches[2]
	}

	// If no valid process executor found or no file extracted, return original command line
	return commandLine
}
