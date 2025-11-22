package tool

import "regexp"

func extractExecFileFromCmd(commandLine string) string {
	// Regexes to extract executable files from command lines for different languages.
	// They support version numbers in commands (e.g., java8, python3.9),
	// handle various command-line arguments, and extract full file paths (absolute or relative)
	// with or without file extensions.

	// Java: First try to match -jar pattern
	javaJarRe := regexp.MustCompile(`\bjava[\d\.-]*\b(?:.*?) -jar\s+([^\s]+)`)
	if matches := javaJarRe.FindStringSubmatch(commandLine); len(matches) > 1 {
		return matches[1]
	}

	// Java: If no -jar, match first non-option argument (main class)
	javaClassRe := regexp.MustCompile(`\bjava[\d\.-]*\b(?:.*?)?\s+([^\s-]\S*)`)
	if matches := javaClassRe.FindStringSubmatch(commandLine); len(matches) > 1 {
		return matches[1]
	}

	// Node.js: Match first non-option argument
	nodeRe := regexp.MustCompile(`\bnode[\d\.-]*\b(?:.*?)?\s+([^\s-]\S*)`)
	if matches := nodeRe.FindStringSubmatch(commandLine); len(matches) > 1 {
		return matches[1]
	}

	// Python: Match first non-option argument
	pythonRe := regexp.MustCompile(`\bpython[\d\.-]*\b(?:.*?)?\s+([^\s-]\S*)`)
	if matches := pythonRe.FindStringSubmatch(commandLine); len(matches) > 1 {
		return matches[1]
	}

	// If no valid process executor found or no file extracted, return original command line
	return commandLine
}
