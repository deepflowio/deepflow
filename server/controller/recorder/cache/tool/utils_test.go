package tool

import (
	"testing"
)

func TestExtractExecFileFromCmd(t *testing.T) {
	testCases := []struct {
		name     string
		command  string
		expected string
	}{
		// Java Test Cases
		{
			name:     "Java with absolute path and options",
			command:  "java -Xmx512m -jar /path/to/app.jar --spring.config.location=./",
			expected: "/path/to/app.jar",
		},
		{
			name:     "Java with version and relative path",
			command:  "java-11-openjdk -jar my/app/run.jar",
			expected: "my/app/run.jar",
		},
		{
			name:     "Java with no .jar extension",
			command:  "java -jar /opt/my-app",
			expected: "/opt/my-app",
		},
		{
			name:     "Java with complex options before -jar",
			command:  "java -Denv=prod --add-modules java.se -jar /app/service.jar",
			expected: "/app/service.jar",
		},
		{
			name:     "Java with complex options without -jar",
			command:  "java -Denv=prod --add-modules java.se service",
			expected: "service",
		},
		{
			name:     "Java simple case",
			command:  "java -Xlog:gc* ProcessMonitor",
			expected: "ProcessMonitor",
		},
		{
			name:     "Java with complex options",
			command:  "java -javaagent:/sidecar/agent/skywalking-agent.jar -Dskywalking.agent.service_name=shop-web -Dskywalking.collector.backend_service=otel-agent.open-telemetry:11800 -jar /home/shop-web-0.0.1-SNAPSHOT.jar",
			expected: "/home/shop-web-0.0.1-SNAPSHOT.jar",
		},
		{
			name:     "Java with absolute process path",
			command:  "/usr/bin/java -Xms256m -Xmx256m -Djava.io.tmpdir=/home/java-app/tmp -jar /home/java-app/lib/app.jar",
			expected: "/home/java-app/lib/app.jar",
		},
		{
			name:     "Java with complex options",
			command:  "/usr/lib/jvm/java-1.8.0-openjdk/bin/java -Xms512m -Xmx512m -Djava.io.tmpdir=/home/nacos/tmp -jar /home/nacos/target/nacos-server.jar",
			expected: "/home/nacos/target/nacos-server.jar",
		},
		{
			name:     "Java with class name and options",
			command:  "java -Xmx512m -Dfile.encoding=UTF-8 com.company.MainClass arg1 arg2",
			expected: "com.company.MainClass",
		},
		{
			name:     "Java with class name and no options",
			command:  "java com.company.MainClass",
			expected: "com.company.MainClass",
		},
		{
			name:     "Java with version and class name",
			command:  "java-11-openjdk com.company.Main",
			expected: "com.company.Main",
		},

		// Node.js Test Cases
		{
			name:     "Node.js with absolute path and options",
			command:  "node --max-old-space-size=4096 /path/to/server.js",
			expected: "/path/to/server.js",
		},
		{
			name:     "Node.js with version and relative path",
			command:  "node14 my/app/index.js arg1",
			expected: "my/app/index.js",
		},
		{
			name:     "Node.js with no .js extension",
			command:  "node /opt/my-server",
			expected: "/opt/my-server",
		},
		{
			name:     "Node.js with inspect option",
			command:  "node --inspect dist/main.js",
			expected: "dist/main.js",
		},
		{
			name:     "Node.js simple case",
			command:  "node app.js",
			expected: "app.js",
		},
		{
			name:     "Node.js mix options",
			command:  "node --max-old-space-size=4096 app.js --config prod",
			expected: "app.js",
		},
		{
			name:     "Node.js with absolute process path",
			command:  "/usr/local/lib/python3.12/site-packages/playwright/driver/node /usr/local/lib/python3.12/site-packages/playwright/driver/package/cli.js run-driver",
			expected: "/usr/local/lib/python3.12/site-packages/playwright/driver/package/cli.js",
		},

		// Python Test Cases
		{
			name:     "Python with absolute path",
			command:  "python3 /path/to/script.py --arg value",
			expected: "/path/to/script.py",
		},
		{
			name:     "Python with version and relative path",
			command:  "python3.9 my/app/main.py",
			expected: "my/app/main.py",
		},
		{
			name:     "Python with no .py extension",
			command:  "python /opt/my-script",
			expected: "/opt/my-script",
		},
		{
			name:     "Python simple case",
			command:  "python script.py",
			expected: "script.py",
		},
		{
			name:     "Python with -m option",
			command:  "python3 -m http.server 8000",
			expected: "http.server",
		},
		{
			name:     "Python with -m option",
			command:  "python3 --bind 192.168.1.100 -m http.server 8000",
			expected: "http.server",
		},

		// No Match Test Cases
		{
			name:     "No match - simple command",
			command:  "ls -l",
			expected: "ls -l",
		},
		{
			name:     "No match - different language",
			command:  "go run main.go",
			expected: "go run main.go",
		},
		{
			name:     "No match - empty string",
			command:  "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := extractExecFileFromCmd(tc.command)
			if actual != tc.expected {
				t.Errorf("For command '%s', expected '%s', but got '%s'", tc.command, tc.expected, actual)
			}
		})
	}
}
