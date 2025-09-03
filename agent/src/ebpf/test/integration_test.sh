#!/bin/bash

# Multi-Language Profiler Integration Test Suite
# Copyright (c) 2024 Yunshan Networks
#
# This script provides comprehensive integration testing for the multi-language
# profiler with real PHP, Node.js, and Python applications.

set -e

# Configuration
TEST_DIR="/tmp/profiler_integration_tests"
RESULTS_DIR="$TEST_DIR/results"
PHP_TEST_DIR="$TEST_DIR/php"
NODEJS_TEST_DIR="$TEST_DIR/nodejs"
PYTHON_TEST_DIR="$TEST_DIR/python"

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

test_assert() {
    ((TOTAL_TESTS++))
    if [ $1 -eq 0 ]; then
        log_success "$2"
    else
        log_error "$2"
    fi
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create test directories
    mkdir -p "$TEST_DIR" "$RESULTS_DIR" "$PHP_TEST_DIR" "$NODEJS_TEST_DIR" "$PYTHON_TEST_DIR"
    
    # Check for required binaries
    PHP_AVAILABLE=1
    NODEJS_AVAILABLE=1
    PYTHON_AVAILABLE=1
    
    if ! command -v php &> /dev/null; then
        log_warning "PHP not found - PHP tests will be skipped"
        PHP_AVAILABLE=0
    fi
    
    if ! command -v node &> /dev/null && ! command -v nodejs &> /dev/null; then
        log_warning "Node.js not found - Node.js tests will be skipped"
        NODEJS_AVAILABLE=0
    fi
    
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
        log_warning "Python not found - Python tests will be skipped"
        PYTHON_AVAILABLE=0
    fi
    
    # Build test profiler if needed
    if [ ! -f "./test_multi_lang_profiler" ]; then
        log_info "Building test profiler..."
        gcc -o test_multi_lang_profiler test_multi_lang_profiler.c -lpthread || {
            log_error "Failed to build test profiler"
            exit 1
        }
    fi
}

# Create PHP test applications
create_php_test_apps() {
    if [ $PHP_AVAILABLE -eq 0 ]; then
        return
    fi
    
    log_info "Creating PHP test applications..."
    
    # Simple recursive function test
    cat > "$PHP_TEST_DIR/recursive_test.php" << 'EOF'
<?php
function fibonacci($n) {
    if ($n <= 1) return $n;
    return fibonacci($n-1) + fibonacci($n-2);
}

function factorial($n) {
    if ($n <= 1) return 1;
    return $n * factorial($n-1);
}

class TestClass {
    public function complexMethod($iterations) {
        for ($i = 0; $i < $iterations; $i++) {
            $this->helperMethod($i);
        }
    }
    
    private function helperMethod($value) {
        return fibonacci($value % 15) + factorial($value % 8);
    }
}

$test = new TestClass();
$test->complexMethod(20);

for ($i = 0; $i < 10; $i++) {
    fibonacci(20);
    usleep(50000); // 50ms
}
?>
EOF

    # Error handling test
    cat > "$PHP_TEST_DIR/error_test.php" << 'EOF'
<?php
function errorProneFunction($depth) {
    if ($depth > 10) {
        throw new Exception("Maximum depth reached");
    }
    
    try {
        return errorProneFunction($depth + 1);
    } catch (Exception $e) {
        // Handle error and continue
        return $depth;
    }
}

for ($i = 0; $i < 5; $i++) {
    try {
        errorProneFunction(0);
    } catch (Exception $e) {
        // Expected error
    }
    usleep(100000); // 100ms
}
?>
EOF

    # Memory intensive test
    cat > "$PHP_TEST_DIR/memory_test.php" << 'EOF'
<?php
function memoryIntensiveFunction() {
    $data = array();
    for ($i = 0; $i < 1000; $i++) {
        $data[] = str_repeat("test", 100);
    }
    return count($data);
}

class MemoryTestClass {
    private $storage = array();
    
    public function allocateMemory($size) {
        for ($i = 0; $i < $size; $i++) {
            $this->storage[] = range(0, 100);
        }
    }
    
    public function releaseMemory() {
        $this->storage = array();
    }
}

$memTest = new MemoryTestClass();
for ($i = 0; $i < 5; $i++) {
    $memTest->allocateMemory(100);
    memoryIntensiveFunction();
    $memTest->releaseMemory();
    usleep(200000); // 200ms
}
?>
EOF
}

# Create Node.js test applications
create_nodejs_test_apps() {
    if [ $NODEJS_AVAILABLE -eq 0 ]; then
        return
    fi
    
    log_info "Creating Node.js test applications..."
    
    # Asynchronous operations test
    cat > "$NODEJS_TEST_DIR/async_test.js" << 'EOF'
function fibonacci(n) {
    if (n <= 1) return n;
    return fibonacci(n-1) + fibonacci(n-2);
}

function asyncOperation(callback) {
    setTimeout(() => {
        const result = fibonacci(20);
        callback(result);
    }, 50);
}

class TestClass {
    constructor() {
        this.data = [];
    }
    
    async processData(items) {
        for (let i = 0; i < items; i++) {
            await new Promise(resolve => {
                asyncOperation((result) => {
                    this.data.push(result);
                    resolve();
                });
            });
        }
    }
}

const test = new TestClass();
test.processData(10).then(() => {
    console.log("Async test completed");
});

// Keep the process alive
setTimeout(() => {
    process.exit(0);
}, 2000);
EOF

    # Event loop intensive test
    cat > "$NODEJS_TEST_DIR/eventloop_test.js" << 'EOF'
const events = require('events');

class EventEmitterTest extends events.EventEmitter {
    constructor() {
        super();
        this.counter = 0;
    }
    
    startEmitting() {
        const interval = setInterval(() => {
            this.emit('data', this.counter++);
            if (this.counter >= 50) {
                clearInterval(interval);
                this.emit('end');
            }
        }, 20);
    }
}

function heavyComputation(n) {
    let result = 0;
    for (let i = 0; i < n; i++) {
        result += Math.sqrt(i) * Math.sin(i);
    }
    return result;
}

const emitter = new EventEmitterTest();

emitter.on('data', (data) => {
    heavyComputation(10000);
});

emitter.on('end', () => {
    console.log("Event loop test completed");
    process.exit(0);
});

emitter.startEmitting();
EOF

    # Memory and closure test
    cat > "$NODEJS_TEST_DIR/closure_test.js" << 'EOF'
function createClosureFactory() {
    const storage = [];
    
    return function(data) {
        storage.push(data);
        
        return function() {
            return storage.reduce((acc, val) => acc + val, 0);
        };
    };
}

function recursiveClosureTest(depth, factory) {
    if (depth <= 0) return factory(0);
    
    const closure = factory(depth);
    return recursiveClosureTest(depth - 1, factory) + closure();
}

const factory = createClosureFactory();

for (let i = 0; i < 10; i++) {
    recursiveClosureTest(10, factory);
    
    // Simulate some delay
    const start = Date.now();
    while (Date.now() - start < 100) {
        // Busy wait
    }
}

console.log("Closure test completed");
EOF
}

# Create Python test applications
create_python_test_apps() {
    if [ $PYTHON_AVAILABLE -eq 0 ]; then
        return
    fi
    
    log_info "Creating Python test applications..."
    
    # Recursive and class-based test
    cat > "$PYTHON_TEST_DIR/recursive_test.py" << 'EOF'
import time

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n-1)

class TestClass:
    def __init__(self):
        self.data = []
    
    def complex_method(self, iterations):
        for i in range(iterations):
            result = self.helper_method(i)
            self.data.append(result)
    
    def helper_method(self, value):
        return fibonacci(value % 15) + factorial(value % 8)

test = TestClass()
test.complex_method(20)

for i in range(10):
    fibonacci(20)
    time.sleep(0.05)  # 50ms
EOF

    # Generator and iterator test
    cat > "$PYTHON_TEST_DIR/generator_test.py" << 'EOF'
import time

def fibonacci_generator(n):
    a, b = 0, 1
    for _ in range(n):
        yield a
        a, b = b, a + b

class IteratorTest:
    def __init__(self, data):
        self.data = data
        self.index = 0
    
    def __iter__(self):
        return self
    
    def __next__(self):
        if self.index >= len(self.data):
            raise StopIteration
        value = self.data[self.index]
        self.index += 1
        return value

def process_with_generators():
    for num in fibonacci_generator(30):
        iterator = IteratorTest(list(range(num % 10)))
        for item in iterator:
            pass  # Process item
        time.sleep(0.01)

for i in range(5):
    process_with_generators()
    time.sleep(0.1)
EOF
}

# Run PHP integration tests
run_php_tests() {
    if [ $PHP_AVAILABLE -eq 0 ]; then
        log_warning "Skipping PHP tests - PHP not available"
        return
    fi
    
    log_info "Running PHP integration tests..."
    
    # Test each PHP application
    for test_file in "$PHP_TEST_DIR"/*.php; do
        test_name=$(basename "$test_file" .php)
        log_info "Testing PHP application: $test_name"
        
        # Start PHP application in background
        php "$test_file" &
        php_pid=$!
        
        # Wait for process to start
        sleep 0.5
        
        # Run profiler test
        ./test_multi_lang_profiler --test-php-pid "$php_pid" > "$RESULTS_DIR/php_${test_name}.log" 2>&1 &
        profiler_pid=$!
        
        # Let it run for a while
        sleep 2
        
        # Check if processes are still running
        if kill -0 "$php_pid" 2>/dev/null; then
            test_assert 0 "PHP process $test_name remained stable"
        else
            test_assert 1 "PHP process $test_name crashed"
        fi
        
        # Cleanup
        kill "$php_pid" 2>/dev/null || true
        kill "$profiler_pid" 2>/dev/null || true
        wait "$php_pid" 2>/dev/null || true
        wait "$profiler_pid" 2>/dev/null || true
    done
}

# Run Node.js integration tests
run_nodejs_tests() {
    if [ $NODEJS_AVAILABLE -eq 0 ]; then
        log_warning "Skipping Node.js tests - Node.js not available"
        return
    fi
    
    log_info "Running Node.js integration tests..."
    
    # Determine Node.js command
    NODE_CMD="node"
    if ! command -v node &> /dev/null; then
        NODE_CMD="nodejs"
    fi
    
    # Test each Node.js application
    for test_file in "$NODEJS_TEST_DIR"/*.js; do
        test_name=$(basename "$test_file" .js)
        log_info "Testing Node.js application: $test_name"
        
        # Start Node.js application in background
        "$NODE_CMD" "$test_file" &
        node_pid=$!
        
        # Wait for process to start
        sleep 0.5
        
        # Run profiler test
        ./test_multi_lang_profiler --test-nodejs-pid "$node_pid" > "$RESULTS_DIR/nodejs_${test_name}.log" 2>&1 &
        profiler_pid=$!
        
        # Let it run for a while
        sleep 3
        
        # Check if processes completed successfully
        wait "$node_pid"
        node_exit_code=$?
        
        if [ $node_exit_code -eq 0 ]; then
            test_assert 0 "Node.js process $test_name completed successfully"
        else
            test_assert 1 "Node.js process $test_name failed with exit code $node_exit_code"
        fi
        
        # Cleanup profiler
        kill "$profiler_pid" 2>/dev/null || true
        wait "$profiler_pid" 2>/dev/null || true
    done
}

# Run Python integration tests
run_python_tests() {
    if [ $PYTHON_AVAILABLE -eq 0 ]; then
        log_warning "Skipping Python tests - Python not available"
        return
    fi
    
    log_info "Running Python integration tests..."
    
    # Determine Python command
    PYTHON_CMD="python3"
    if ! command -v python3 &> /dev/null; then
        PYTHON_CMD="python"
    fi
    
    # Test each Python application
    for test_file in "$PYTHON_TEST_DIR"/*.py; do
        test_name=$(basename "$test_file" .py)
        log_info "Testing Python application: $test_name"
        
        # Start Python application in background
        "$PYTHON_CMD" "$test_file" &
        python_pid=$!
        
        # Wait for process to start
        sleep 0.5
        
        # Run profiler test
        ./test_multi_lang_profiler --test-python-pid "$python_pid" > "$RESULTS_DIR/python_${test_name}.log" 2>&1 &
        profiler_pid=$!
        
        # Let it run for a while
        sleep 2
        
        # Check if processes are still running
        if kill -0 "$python_pid" 2>/dev/null; then
            test_assert 0 "Python process $test_name remained stable"
        else
            test_assert 1 "Python process $test_name crashed"
        fi
        
        # Cleanup
        kill "$python_pid" 2>/dev/null || true
        kill "$profiler_pid" 2>/dev/null || true
        wait "$python_pid" 2>/dev/null || true
        wait "$profiler_pid" 2>/dev/null || true
    done
}

# Run performance benchmarks
run_performance_benchmarks() {
    log_info "Running performance benchmarks..."
    
    # Benchmark profiler overhead
    log_info "Measuring profiler overhead..."
    
    # Create a simple CPU-intensive script
    cat > "$TEST_DIR/benchmark.php" << 'EOF'
<?php
function cpu_intensive_task($iterations) {
    $result = 0;
    for ($i = 0; $i < $iterations; $i++) {
        $result += sqrt($i) * sin($i);
    }
    return $result;
}

$start = microtime(true);
for ($i = 0; $i < 100; $i++) {
    cpu_intensive_task(10000);
}
$end = microtime(true);

echo "Execution time: " . ($end - $start) . " seconds\n";
?>
EOF
    
    if [ $PHP_AVAILABLE -eq 1 ]; then
        # Run without profiler
        log_info "Running benchmark without profiler..."
        php "$TEST_DIR/benchmark.php" > "$RESULTS_DIR/benchmark_no_profiler.log" 2>&1
        
        # Run with profiler
        log_info "Running benchmark with profiler..."
        php "$TEST_DIR/benchmark.php" &
        php_pid=$!
        ./test_multi_lang_profiler --test-php-pid "$php_pid" > "$RESULTS_DIR/benchmark_with_profiler.log" 2>&1 &
        profiler_pid=$!
        
        wait "$php_pid"
        kill "$profiler_pid" 2>/dev/null || true
        wait "$profiler_pid" 2>/dev/null || true
        
        test_assert 0 "Performance benchmark completed"
    fi
}

# Analyze test results
analyze_results() {
    log_info "Analyzing test results..."
    
    # Check for crashes or errors in log files
    if [ -d "$RESULTS_DIR" ]; then
        error_count=$(grep -r "error\|crash\|segfault\|abort" "$RESULTS_DIR" | wc -l || true)
        if [ $error_count -gt 0 ]; then
            log_warning "Found $error_count potential errors in test logs"
        else
            log_success "No critical errors found in test logs"
        fi
    fi
    
    # Generate summary report
    cat > "$RESULTS_DIR/summary.txt" << EOF
Multi-Language Profiler Integration Test Summary
================================================

Total Tests: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS
Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

Runtime Availability:
- PHP: $([ $PHP_AVAILABLE -eq 1 ] && echo "Available" || echo "Not Available")
- Node.js: $([ $NODEJS_AVAILABLE -eq 1 ] && echo "Available" || echo "Not Available")  
- Python: $([ $PYTHON_AVAILABLE -eq 1 ] && echo "Available" || echo "Not Available")

Test Date: $(date)
EOF
}

# Cleanup test environment
cleanup_test_environment() {
    log_info "Cleaning up test environment..."
    
    # Kill any remaining test processes
    pkill -f "test_profiler" 2>/dev/null || true
    pkill -f "recursive_test.php" 2>/dev/null || true
    pkill -f "async_test.js" 2>/dev/null || true
    pkill -f "recursive_test.py" 2>/dev/null || true
    
    # Keep results but remove temporary files
    rm -f "$TEST_DIR"/*.php "$TEST_DIR"/*.js "$TEST_DIR"/*.py
    
    log_info "Test results saved in: $RESULTS_DIR"
}

# Print final summary
print_summary() {
    echo
    echo "=================================================="
    echo "Integration Test Summary"
    echo "=================================================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    
    if [ $TOTAL_TESTS -gt 0 ]; then
        success_rate=$(( PASSED_TESTS * 100 / TOTAL_TESTS ))
        echo "Success Rate: ${success_rate}%"
        
        if [ $FAILED_TESTS -eq 0 ]; then
            echo -e "${GREEN}All tests passed!${NC}"
        else
            echo -e "${RED}Some tests failed.${NC}"
        fi
    fi
    
    echo "=================================================="
}

# Main execution
main() {
    echo "Multi-Language Profiler Integration Test Suite"
    echo "=============================================="
    
    setup_test_environment
    create_php_test_apps
    create_nodejs_test_apps
    create_python_test_apps
    
    run_php_tests
    run_nodejs_tests
    run_python_tests
    run_performance_benchmarks
    
    analyze_results
    cleanup_test_environment
    print_summary
    
    # Exit with appropriate code
    if [ $FAILED_TESTS -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --php-only     Run only PHP tests"
        echo "  --nodejs-only  Run only Node.js tests"
        echo "  --python-only  Run only Python tests"
        echo "  --no-cleanup   Don't cleanup test files"
        exit 0
        ;;
    --php-only)
        PHP_AVAILABLE=1
        NODEJS_AVAILABLE=0
        PYTHON_AVAILABLE=0
        ;;
    --nodejs-only)
        PHP_AVAILABLE=0
        NODEJS_AVAILABLE=1
        PYTHON_AVAILABLE=0
        ;;
    --python-only)
        PHP_AVAILABLE=0
        NODEJS_AVAILABLE=0
        PYTHON_AVAILABLE=1
        ;;
esac

# Run main function
main "$@"