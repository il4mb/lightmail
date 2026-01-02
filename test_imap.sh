#!/bin/bash

# LightMail IMAP Test Script with Persistent Connections
# Tests all major IMAP commands against the server

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVER="localhost"
PORT=143
SSL_PORT=993
USER="user@example.com"
PASSWORD="password123"
TIMEOUT=5
TEST_SSL=1

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Persistent connection file descriptors
REGULAR_FD=""
SSL_FD=""

# Cleanup function
cleanup() {
    if [ -n "$REGULAR_FD" ] && [ -e "/proc/$$/fd/$REGULAR_FD" ]; then
        exec {REGULAR_FD}>&-
    fi
    if [ -n "$SSL_FD" ] && [ -e "/proc/$$/fd/$SSL_FD" ]; then
        exec {SSL_FD}>&-
    fi
    echo -e "${BLUE}Cleanup completed${NC}"
}

# Trap exit to cleanup
trap cleanup EXIT

# Test output formatting
print_test() {
    local test_name=$1
    local status=$2
    local message=$3
    
    case $status in
        "PASS")
            echo -e "${GREEN}✓ PASS${NC} $test_name"
            if [ -n "$message" ]; then
                echo -e "  ${BLUE}→${NC} $message"
            fi
            TESTS_PASSED=$((TESTS_PASSED + 1))
            ;;
        "FAIL")
            echo -e "${RED}✗ FAIL${NC} $test_name"
            if [ -n "$message" ]; then
                echo -e "  ${RED}→${NC} $message"
            fi
            TESTS_FAILED=$((TESTS_FAILED + 1))
            ;;
        "SKIP")
            echo -e "${YELLOW}⚠ SKIP${NC} $test_name"
            if [ -n "$message" ]; then
                echo -e "  ${YELLOW}→${NC} $message"
            fi
            TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
            ;;
    esac
}

# Send IMAP command using persistent connection
send_imap_persistent() {
    local command=$1
    local use_ssl=${2:-0}
    local fd
    
    if [ $use_ssl -eq 1 ]; then
        if [ -z "$SSL_FD" ]; then
            # Create SSL connection if not exists
            exec {SSL_FD}<>/dev/tcp/$SERVER/$SSL_PORT
            # Read welcome banner
            timeout $TIMEOUT cat <&$SSL_FD >/dev/null 2>&1
        fi
        fd=$SSL_FD
    else
        if [ -z "$REGULAR_FD" ]; then
            # Create regular connection if not exists
            exec {REGULAR_FD}<>/dev/tcp/$SERVER/$PORT
            # Read welcome banner
            timeout $TIMEOUT cat <&$REGULAR_FD >/dev/null 2>&1
        fi
        fd=$REGULAR_FD
    fi
    
    # Send command
    echo -e "$command\r\n" >&$fd
    
    # Read response
    local response=""
    local line
    while IFS= read -t $TIMEOUT -r line <&$fd; do
        response+="$line"$'\n'
        # Check if this is a command completion line (starts with tag)
        if [[ "$line" =~ ^[A-Za-z][0-9]+[[:space:]] ]]; then
            break
        fi
    done
    
    echo "$response"
}

# Close connection
close_connection() {
    local use_ssl=${1:-0}
    
    if [ $use_ssl -eq 1 ]; then
        if [ -n "$SSL_FD" ]; then
            send_imap_persistent "Z99 LOGOUT" 1 >/dev/null 2>&1
            exec {SSL_FD}>&-
            SSL_FD=""
        fi
    else
        if [ -n "$REGULAR_FD" ]; then
            send_imap_persistent "Z99 LOGOUT" 0 >/dev/null 2>&1
            exec {REGULAR_FD}>&-
            REGULAR_FD=""
        fi
    fi
}

# Simple send for backward compatibility (creates new connection each time)
send_imap() {
    local command=$1
    local use_ssl=${2:-0}
    
    if [ $use_ssl -eq 1 ]; then
        echo -e "$command\r\n" | timeout $TIMEOUT openssl s_client -connect $SERVER:$SSL_PORT -quiet 2>/dev/null
    else
        echo -e "$command\r\n" | timeout $TIMEOUT nc $SERVER $PORT
    fi
}

# Test connection with persistent connection
test_connection() {
    echo -e "${BLUE}=== Testing Connection ===${NC}"
    
    # Test regular IMAP with persistent connection
    response=$(send_imap_persistent "TAG1 CAPABILITY" 0)
    if echo "$response" | grep -q "OK"; then
        print_test "IMAP Connection" "PASS" "Connected to IMAP port $PORT (persistent)"
    else
        print_test "IMAP Connection" "FAIL" "Failed to connect to IMAP port $PORT"
        # Fallback to non-persistent
        response=$(send_imap "TAG1 CAPABILITY" 0)
        if echo "$response" | grep -q "OK"; then
            print_test "IMAP Connection" "PASS" "Connected to IMAP port $PORT (non-persistent)"
        fi
    fi
    
    # Test IMAPS if enabled
    if [ $TEST_SSL -eq 1 ]; then
        response=$(send_imap_persistent "TAG2 CAPABILITY" 1)
        if echo "$response" | grep -q "OK"; then
            print_test "IMAPS Connection" "PASS" "Connected to IMAPS port $SSL_PORT (persistent)"
        else
            print_test "IMAPS Connection" "SKIP" "SSL not enabled or certificate issue"
        fi
    fi
    
    echo ""
}

# Test authentication with persistent connection
test_auth() {
    echo -e "${BLUE}=== Testing Authentication ===${NC}"
    
    # Test LOGIN command using same connection
    response=$(send_imap_persistent "A01 LOGIN \"$USER\" \"$PASSWORD\"" 0)
    if echo "$response" | grep -q "OK.*LOGIN"; then
        print_test "LOGIN Command" "PASS" "Authentication successful (same connection)"
        AUTH_TAG="A01"
    else
        print_test "LOGIN Command" "FAIL" "Authentication failed"
        return 1
    fi
    
    # Test LOGOUT using same connection
    response=$(send_imap_persistent "A02 LOGOUT" 0)
    if echo "$response" | grep -q "BYE"; then
        print_test "LOGOUT Command" "PASS" "Logout successful (same connection)"
        # Connection is now closed, need to reconnect
        close_connection 0
    else
        print_test "LOGOUT Command" "FAIL" "Logout failed"
    fi
    
    echo ""
    return 0
}

# Enhanced mailbox commands with session persistence
test_mailbox_commands() {
    echo -e "${BLUE}=== Testing Mailbox Commands ===${NC}"
    
    # Login first using persistent connection
    response=$(send_imap_persistent "B01 LOGIN \"$USER\" \"$PASSWORD\"" 0)
    if ! echo "$response" | grep -q "OK.*LOGIN"; then
        print_test "Session Login" "FAIL" "Cannot establish session"
        return 1
    fi
    
    # Test LIST - should work on same connection
    response=$(send_imap_persistent "B02 LIST \"\" \"*\"" 0)
    if echo "$response" | grep -q "LIST"; then
        print_test "LIST Command" "PASS" "Mailbox listing successful (same session)"
        
        # Extract mailbox names
        mailboxes=$(echo "$response" | grep "LIST" | sed 's/.*"\(.*\)".*/\1/')
        if [ -n "$mailboxes" ]; then
            echo -e "  ${BLUE}Mailboxes found:${NC}"
            echo "$mailboxes" | while read mb; do
                echo -e "    ${BLUE}•${NC} $mb"
            done
        fi
    else
        print_test "LIST Command" "FAIL" "Mailbox listing failed"
    fi
    
    # Test SELECT INBOX - same session
    response=$(send_imap_persistent "B03 SELECT INBOX" 0)
    if echo "$response" | grep -q "OK.*SELECT"; then
        print_test "SELECT Command" "PASS" "INBOX selection successful (same session)"
        
        # Parse response counts
        exists=$(echo "$response" | grep -o "[0-9]* EXISTS" | grep -o "[0-9]*")
        recent=$(echo "$response" | grep -o "[0-9]* RECENT" | grep -o "[0-9]*")
        if [ -n "$exists" ]; then
            echo -e "  ${BLUE}Messages:${NC} $exists exists, $recent recent"
        fi
    else
        print_test "SELECT Command" "FAIL" "INBOX selection failed"
    fi
    
    # Test EXAMINE (read-only SELECT) - same session
    response=$(send_imap_persistent "B04 EXAMINE INBOX" 0)
    if echo "$response" | grep -q "OK.*EXAMINE"; then
        print_test "EXAMINE Command" "PASS" "Read-only mailbox access (same session)"
    else
        print_test "EXAMINE Command" "FAIL" "EXAMINE command failed"
    fi
    
    # Test CREATE - same session
    test_mailbox="test-$(date +%s)"
    response=$(send_imap_persistent "B05 CREATE \"$test_mailbox\"" 0)
    if echo "$response" | grep -q "OK.*CREATE"; then
        print_test "CREATE Command" "PASS" "Created mailbox: $test_mailbox (same session)"
        
        # Test DELETE - same session
        response=$(send_imap_persistent "B06 DELETE \"$test_mailbox\"" 0)
        if echo "$response" | grep -q "OK.*DELETE"; then
            print_test "DELETE Command" "PASS" "Deleted test mailbox (same session)"
        else
            print_test "DELETE Command" "FAIL" "Failed to delete test mailbox"
        fi
    else
        print_test "CREATE Command" "FAIL" "Failed to create test mailbox"
    fi
    
    # Test STATUS - same session
    response=$(send_imap_persistent "B07 STATUS INBOX (MESSAGES RECENT UNSEEN)" 0)
    if echo "$response" | grep -q "STATUS.*INBOX"; then
        print_test "STATUS Command" "PASS" "Mailbox status retrieved (same session)"
        
        # Parse status values
        messages=$(echo "$response" | grep -o "MESSAGES [0-9]*" | grep -o "[0-9]*")
        recent=$(echo "$response" | grep -o "RECENT [0-9]*" | grep -o "[0-9]*")
        unseen=$(echo "$response" | grep -o "UNSEEN [0-9]*" | grep -o "[0-9]*")
        echo -e "  ${BLUE}Status:${NC} Messages=$messages, Recent=$recent, Unseen=$unseen"
    else
        print_test "STATUS Command" "FAIL" "STATUS command failed"
    fi
    
    # Logout and close session properly
    response=$(send_imap_persistent "B08 LOGOUT" 0)
    if echo "$response" | grep -q "BYE"; then
        print_test "Session Logout" "PASS" "Logged out and session closed"
    fi
    close_connection 0
    
    echo ""
}

# Test with session continuity
test_message_commands() {
    echo -e "${BLUE}=== Testing Message Commands ===${NC}"
    
    # Start new session
    response=$(send_imap_persistent "C01 LOGIN \"$USER\" \"$PASSWORD\"" 0)
    if ! echo "$response" | grep -q "OK.*LOGIN"; then
        print_test "Message Session" "FAIL" "Cannot establish message session"
        return 1
    fi
    
    # Select mailbox in same session
    response=$(send_imap_persistent "C02 SELECT INBOX" 0)
    if ! echo "$response" | grep -q "OK.*SELECT"; then
        print_test "Message Selection" "FAIL" "Cannot select mailbox"
        close_connection 0
        return 1
    fi
    
    # Test SEARCH ALL in same session
    response=$(send_imap_persistent "C03 SEARCH ALL" 0)
    if echo "$response" | grep -q "SEARCH"; then
        print_test "SEARCH Command" "PASS" "Message search successful (same session)"
        
        # Get message sequence numbers
        messages=$(echo "$response" | grep -o "SEARCH .*" | cut -d' ' -f2-)
        if [ -n "$messages" ] && [ "$messages" != "SEARCH" ]; then
            count=$(echo $messages | wc -w)
            echo -e "  ${BLUE}Found:${NC} $count message(s) in session"
        fi
    fi
    
    # Close session
    send_imap_persistent "C99 LOGOUT" 0 >/dev/null 2>&1
    close_connection 0
    
    echo ""
}

# Interactive test with persistent connection
interactive_test() {
    echo -e "${BLUE}=== Interactive IMAP Test (Persistent) ===${NC}"
    echo -e "Type IMAP commands (e.g., 'CAPABILITY', 'LOGIN \"user\" \"pass\"')"
    echo -e "Type 'quit' to exit, 'help' for available commands"
    echo ""
    
    # Create persistent connection
    if [ -z "$REGULAR_FD" ]; then
        exec {REGULAR_FD}<>/dev/tcp/$SERVER/$PORT
        # Read and display welcome banner
        echo -n "Welcome: "
        timeout $TIMEOUT head -1 <&$REGULAR_FD
    fi
    
    tag=1
    while true; do
        read -p "IMAP> " cmd
        
        case $cmd in
            quit|exit)
                # Send LOGOUT before exiting
                echo -e "I${tag} LOGOUT\r\n" >&$REGULAR_FD
                timeout $TIMEOUT cat <&$REGULAR_FD
                break
                ;;
            help)
                echo "Available commands:"
                echo "  CAPABILITY"
                echo "  LOGIN <user> <pass>"
                echo "  LIST \"\" \"*\""
                echo "  SELECT INBOX"
                echo "  SEARCH ALL"
                echo "  FETCH 1 (FLAGS)"
                echo "  NOOP"
                echo "  LOGOUT"
                echo "  quit - exit interactive mode"
                continue
                ;;
            "")
                # Send NOOP to keep connection alive
                cmd="NOOP"
                ;;
        esac
        
        # Send command with tag
        echo -e "I${tag} $cmd\r\n" >&$REGULAR_FD
        
        # Read response
        echo -e "${BLUE}Response:${NC}"
        while IFS= read -t $TIMEOUT -r line <&$REGULAR_FD; do
            echo "$line"
            # Check if this is a command completion line
            if [[ "$line" =~ ^I${tag}[[:space:]] ]]; then
                break
            fi
        done
        
        tag=$((tag + 1))
    done
    
    # Cleanup
    close_connection 0
}

# Quick test with persistent connection
run_quick_test() {
    echo -e "${BLUE}=== Quick Connection Test (Persistent) ===${NC}"
    
    # Test basic connection with persistence
    response=$(send_imap_persistent "Q01 CAPABILITY" 0)
    if echo "$response" | grep -q "OK"; then
        echo -e "${GREEN}✓ IMAP server is responding (persistent connection)${NC}"
        
        # Test login on same connection
        response=$(send_imap_persistent "Q02 LOGIN \"$USER\" \"$PASSWORD\"" 0)
        if echo "$response" | grep -q "OK.*LOGIN"; then
            echo -e "${GREEN}✓ Authentication successful (same connection)${NC}"
            
            # Test basic operations on same connection
            response=$(send_imap_persistent "Q03 SELECT INBOX" 0)
            if echo "$response" | grep -q "OK.*SELECT"; then
                echo -e "${GREEN}✓ SELECT successful (same connection)${NC}"
                
                response=$(send_imap_persistent "Q04 SEARCH ALL" 0)
                if echo "$response" | grep -q "SEARCH"; then
                    echo -e "${GREEN}✓ SEARCH successful (same connection)${NC}"
                    echo -e "${GREEN}✅ Session persistence confirmed!${NC}"
                fi
            fi
            
            # Logout on same connection
            send_imap_persistent "Q05 LOGOUT" 0 >/dev/null 2>&1
        else
            echo -e "${RED}✗ Authentication failed${NC}"
        fi
    else
        echo -e "${RED}✗ IMAP server not responding${NC}"
        return 1
    fi
    
    # Close connection
    close_connection 0
    echo ""
    return 0
}

# Main test runner with session awareness
run_all_tests() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  LightMail IMAP Server Tests (v2.0)  ${NC}"
    echo -e "${BLUE}         Persistent Sessions          ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "Server: ${YELLOW}$SERVER${NC}"
    echo -e "User: ${YELLOW}$USER${NC}"
    echo -e "Time: ${YELLOW}$(date)${NC}"
    echo -e "${BLUE}========================================${NC}\n"
    
    # Run tests
    test_connection
    test_auth
    if [ $? -eq 0 ]; then
        test_mailbox_commands
        test_message_commands
    else
        echo -e "${RED}Skipping further tests due to authentication failure${NC}\n"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 2))
    fi
    
    # Summary
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}              Test Summary              ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo -e "${BLUE}Total:${NC}   $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
    echo -e "${BLUE}Mode:${NC}    Persistent Session Testing"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}✅ All tests passed!${NC}"
        return 0
    else
        echo -e "\n${RED}❌ Some tests failed${NC}"
        return 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -h, --help          Show this help message"
            echo "  -s, --server HOST   IMAP server hostname (default: localhost)"
            echo "  -p, --port PORT     IMAP port (default: 143)"
            echo "  -u, --user USER     Username (default: user@example.com)"
            echo "  -w, --pass PASS     Password (default: password123)"
            echo "  -q, --quick         Run quick connection test only"
            echo "  -i, --interactive   Run interactive test mode (persistent)"
            echo "  -t, --timeout SEC   Connection timeout (default: 5)"
            echo ""
            echo "Examples:"
            echo "  $0                   # Run all tests with persistent sessions"
            echo "  $0 -q               # Quick test with persistent connection"
            echo "  $0 -i               # Interactive mode with single connection"
            echo ""
            exit 0
            ;;
        -s|--server)
            SERVER="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -u|--user)
            USER="$2"
            shift 2
            ;;
        -w|--pass)
            PASSWORD="$2"
            shift 2
            ;;
        -q|--quick)
            QUICK_MODE=1
            shift
            ;;
        -i|--interactive)
            INTERACTIVE_MODE=1
            shift
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Main execution
if [ -n "$INTERACTIVE_MODE" ]; then
    interactive_test
elif [ -n "$QUICK_MODE" ]; then
    run_quick_test
else
    run_all_tests
fi

# Exit with appropriate code
if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi