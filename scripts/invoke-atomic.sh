#!/bin/bash
# Invoke Atomic Red Team Tests
# Wrapper script for running Atomic Red Team tests in the detection lab

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ATOMIC_PATH="/opt/atomic-red-team"
LINUX_CONTAINER="detection-lab-linux-target"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_blue() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

show_help() {
    cat << EOF
Invoke Atomic Red Team Tests

Usage: $0 [OPTIONS] <TECHNIQUE_ID>

Arguments:
    TECHNIQUE_ID    MITRE ATT&CK technique ID (e.g., T1003, T1003.001)

Options:
    -l, --list           List available tests for a technique
    -s, --show           Show test details without executing
    -t, --target TARGET  Target system (linux, windows)
    -n, --test-number N  Run specific test number
    -c, --cleanup        Run cleanup commands after test
    --dry-run            Show commands without executing
    -h, --help           Show this help message

Examples:
    # List tests for credential access technique
    $0 -l T1003

    # Run all Linux tests for T1003.001
    $0 -t linux T1003.001

    # Show test details
    $0 -s T1003.001

    # Run specific test number
    $0 -t linux -n 1 T1003.001

    # Run test with cleanup
    $0 -c -t linux T1003.001

Environment:
    LINUX_CONTAINER   Container name for Linux tests (default: $LINUX_CONTAINER)

EOF
}

check_container_running() {
    local container="$1"
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        log_error "Container '$container' is not running"
        log_info "Start the lab with: make up"
        exit 1
    fi
}

list_tests() {
    local technique="$1"
    log_info "Available tests for $technique:"
    echo ""

    # Check Linux container for Atomic tests
    check_container_running "$LINUX_CONTAINER"

    docker exec "$LINUX_CONTAINER" bash -c "
        if [ -d '$ATOMIC_PATH/atomics/$technique' ]; then
            cat '$ATOMIC_PATH/atomics/$technique/$technique.yaml' 2>/dev/null | \
            grep -E '^  - name:|^    name:|supported_platforms:' | head -30
        else
            echo 'Technique not found: $technique'
            echo 'Available techniques:'
            ls '$ATOMIC_PATH/atomics/' | head -20
        fi
    "
}

show_test() {
    local technique="$1"
    log_info "Test details for $technique:"
    echo ""

    check_container_running "$LINUX_CONTAINER"

    docker exec "$LINUX_CONTAINER" bash -c "
        if [ -f '$ATOMIC_PATH/atomics/$technique/$technique.yaml' ]; then
            cat '$ATOMIC_PATH/atomics/$technique/$technique.yaml'
        else
            echo 'Technique not found: $technique'
        fi
    "
}

run_linux_test() {
    local technique="$1"
    local test_num="$2"
    local cleanup="$3"
    local dry_run="$4"

    check_container_running "$LINUX_CONTAINER"

    log_blue "Running Atomic test: $technique on Linux"

    if [ -n "$dry_run" ]; then
        log_warn "DRY RUN - Commands will not be executed"
    fi

    # Build the command
    local cmd="cd $ATOMIC_PATH && "

    # Check if test exists
    if ! docker exec "$LINUX_CONTAINER" test -d "$ATOMIC_PATH/atomics/$technique"; then
        log_error "Technique $technique not found"
        exit 1
    fi

    # For now, run the test commands directly from the YAML
    # In a full implementation, you'd use Invoke-AtomicRedTeam or a Python parser
    log_info "Executing test from: $ATOMIC_PATH/atomics/$technique/"

    if [ -n "$dry_run" ]; then
        docker exec "$LINUX_CONTAINER" bash -c "
            echo 'Would execute commands from:'
            cat '$ATOMIC_PATH/atomics/$technique/$technique.yaml' | grep -A5 'executor:'
        "
    else
        # Simple execution - extract and run bash commands
        # Note: This is simplified; a production version would parse YAML properly
        docker exec "$LINUX_CONTAINER" bash -c "
            cd '$ATOMIC_PATH/atomics/$technique'
            echo 'Executing test for $technique'
            echo '================================'

            # Log the test execution
            echo \"\$(date): Running $technique\" >> /var/log/atomic-tests.log

            # Try to find and execute the test script
            if [ -f 'src/linux/run.sh' ]; then
                bash src/linux/run.sh
            elif [ -f 'run.sh' ]; then
                bash run.sh
            else
                echo 'Manual execution required. See test YAML for commands.'
                cat '$technique.yaml' | grep -A10 'executor:' | head -15
            fi
        "
    fi

    if [ -n "$cleanup" ] && [ -z "$dry_run" ]; then
        log_info "Running cleanup..."
        docker exec "$LINUX_CONTAINER" bash -c "
            cd '$ATOMIC_PATH/atomics/$technique'
            if [ -f 'src/linux/cleanup.sh' ]; then
                bash src/linux/cleanup.sh
            fi
        "
    fi

    log_info "Test complete. Check logs for detection validation."
}

run_windows_test() {
    local technique="$1"
    local test_num="$2"

    log_blue "Windows tests require manual execution on the Windows VM"
    echo ""
    cat << EOF
To run Atomic tests on Windows:

1. Connect to the Windows VM via RDP
2. Open PowerShell as Administrator
3. Run:

   Import-Module Invoke-AtomicRedTeam
   Invoke-AtomicTest $technique -ShowDetails
   Invoke-AtomicTest $technique

For specific test number:
   Invoke-AtomicTest $technique -TestNumbers $test_num

With cleanup:
   Invoke-AtomicTest $technique -Cleanup

EOF
}

# Parse arguments
TARGET=""
TECHNIQUE=""
LIST_TESTS=""
SHOW_TEST=""
TEST_NUM=""
CLEANUP=""
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--list)
            LIST_TESTS="1"
            shift
            ;;
        -s|--show)
            SHOW_TEST="1"
            shift
            ;;
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -n|--test-number)
            TEST_NUM="$2"
            shift 2
            ;;
        -c|--cleanup)
            CLEANUP="1"
            shift
            ;;
        --dry-run)
            DRY_RUN="1"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        T*)
            TECHNIQUE="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate inputs
if [ -z "$TECHNIQUE" ]; then
    log_error "Technique ID required"
    show_help
    exit 1
fi

# Execute requested action
if [ -n "$LIST_TESTS" ]; then
    list_tests "$TECHNIQUE"
    exit 0
fi

if [ -n "$SHOW_TEST" ]; then
    show_test "$TECHNIQUE"
    exit 0
fi

# Default to Linux if no target specified
TARGET="${TARGET:-linux}"

case "$TARGET" in
    linux)
        run_linux_test "$TECHNIQUE" "$TEST_NUM" "$CLEANUP" "$DRY_RUN"
        ;;
    windows)
        run_windows_test "$TECHNIQUE" "$TEST_NUM"
        ;;
    *)
        log_error "Unknown target: $TARGET (use 'linux' or 'windows')"
        exit 1
        ;;
esac
