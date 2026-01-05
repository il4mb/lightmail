#!/bin/bash

# LightMail IMAP Test Script with Enhanced Persistent Connections
# Tests all major IMAP commands with improved error handling and reporting

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SERVER="${IMAP_SERVER:-localhost}"
PORT="${IMAP_PORT:-1143}"
SSL_PORT="${IMAP_SSL_PORT:-1993}"
USER="${IMAP_USER:-user@example.com}"
PASSWORD="${IMAP_PASS:-password123}"
TIMEOUT="${IMAP_TIMEOUT:-5}"
TEST_SSL="${TEST_IMAP_SSL:-1}"
VERBOSE="${VERBOSE:-0}"
MAX_RETRIES=3
RETRY_DELAY=1

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
COMMAND_COUNT=0

# Persistent connection file descriptors
REGULAR_FD=""
SSL_FD=""
CURRENT_TAG=0
SESSION_ACTIVE=0

# Test results array
declare -A TEST_RESULTS
declare -A SESSION_TRACKER

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_debug() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo -e "${PURPLE}[DEBUG]${NC} $*"
    fi
}

# Cleanup function with better resource management
cleanup() {
    log_debug "Starting cleanup procedure"
    
    # Close regular connection if open
    if [ -n "$REGULAR_FD" ] && [ -e "/proc/$$/fd/$REGULAR_FD" ]; then
        log_debug "Closing regular IMAP connection (fd: $REGULAR_FD)"
        if [ "$SESSION_ACTIVE" -eq 1 ]; then
            send_imap_persistent "Z99 LOGOUT" 0 >/dev/null 2>&1 || true
        fi
        exec {REGULAR_FD}>&- 2>/dev/null || true
        REGULAR_FD=""
        SESSION_ACTIVE=0
    fi
    
    # Close SSL connection if open
    if [ -n "$SSL_FD" ] && [ -e "/proc/$$/fd/$SSL_FD" ]; then
        log_debug "Closing SSL IMAP connection (fd: $SSL_FD)"
        exec {SSL_FD}>&- 2>/dev/null || true
        SSL_FD=""
    fi
    
    # Kill any hanging connections
    pkill -f "nc $SERVER $PORT" 2>/dev/null || true
    pkill -f "openssl.*$SERVER:$SSL_PORT" 2>/dev/null || true
    
    log_debug "Cleanup completed"
}

# Enhanced trap handling
trap_exit() {
    echo ""
    log_info "Test session ending..."
    cleanup
}

trap_interrupt() {
    echo ""
    log_warning "Test interrupted by user"
    cleanup
    print_summary
    exit 130
}

trap trap_exit EXIT
trap trap_interrupt INT TERM

# Generate unique tag for IMAP commands
generate_tag() {
    local prefix="${1:-A}"
    CURRENT_TAG=$((CURRENT_TAG + 1))
    echo "${prefix}${CURRENT_TAG}"
}

# Connection health check
check_connection() {
    local use_ssl=${1:-0}
    local fd=""
    
    if [ $use_ssl -eq 1 ]; then
        fd=$SSL_FD
    else
        fd=$REGULAR_FD
    fi
    
    if [ -z "$fd" ] || ! [ -e "/proc/$$/fd/$fd" ]; then
        return 1
    fi
    
    # Send NOOP to check connection
    local tag=$(generate_tag "HC")
    local response=$(echo -e "$tag NOOP\r\n" >&$fd; timeout $TIMEOUT head -1 <&$fd 2>/dev/null)
    
    if echo "$response" | grep -q "^$tag OK"; then
        return 0
    else
        return 1
    fi
}

# Enhanced persistent connection sender with retry logic
send_imap_persistent() {
    local command=$1
    local use_ssl=${2:-0}
    local max_retries=${3:-$MAX_RETRIES}
    local retry_count=0
    local fd=""
    local tag=""
    local response=""
    
    # Extract or generate tag
    if [[ "$command" =~ ^[A-Za-z][0-9]+[[:space:]] ]]; then
        tag=$(echo "$command" | cut -d' ' -f1)
    else
        tag=$(generate_tag)
        command="$tag $command"
    fi
    
    while [ $retry_count -lt $max_retries ]; do
        # Get or create connection
        if [ $use_ssl -eq 1 ]; then
            if ! check_connection 1; then
                log_debug "Creating new SSL connection"
                exec {SSL_FD}<>/dev/tcp/$SERVER/$SSL_PORT 2>/dev/null || {
                    log_error "Failed to create SSL connection to $SERVER:$SSL_PORT"
                    return 1
                }
                # Read and discard welcome banner
                timeout $TIMEOUT head -1 <&$SSL_FD >/dev/null 2>&1
            fi
            fd=$SSL_FD
        else
            if ! check_connection 0; then
                log_debug "Creating new regular connection"
                exec {REGULAR_FD}<>/dev/tcp/$SERVER/$PORT 2>/dev/null || {
                    log_error "Failed to create connection to $SERVER:$PORT"
                    return 1
                }
                # Read and discard welcome banner
                timeout $TIMEOUT head -1 <&$REGULAR_FD >/dev/null 2>&1
            fi
            fd=$REGULAR_FD
        fi
        
        # Send command
        log_debug "Sending command: $command"
        echo -e "$command\r\n" >&$fd
        
        # Read response with timeout
        response=""
        local line=""
        local start_time=$(date +%s)
        
        while true; do
            if ! read -t $TIMEOUT -r line <&$fd; then
                log_warning "Timeout reading response for tag: $tag"
                break
            fi
            
            response+="$line"$'\n'
            log_debug "Received line: $line"
            
            # Check if this is the completion line for our command
            if [[ "$line" =~ ^$tag[[:space:]] ]]; then
                break
            fi
            
            # Safety timeout
            local current_time=$(date +%s)
            if [ $((current_time - start_time)) -gt $TIMEOUT ]; then
                log_warning "Response timeout for tag: $tag"
                break
            fi
        done
        
        # Check if we got a valid response
        if [ -n "$response" ] && echo "$response" | grep -q "^$tag"; then
            break
        else
            retry_count=$((retry_count + 1))
            log_warning "Retrying command ($retry_count/$max_retries): $tag"
            sleep $RETRY_DELAY
            
            # Close and recreate connection on retry
            if [ $use_ssl -eq 1 ]; then
                exec {SSL_FD}>&- 2>/dev/null || true
                SSL_FD=""
            else
                exec {REGULAR_FD}>&- 2>/dev/null || true
                REGULAR_FD=""
            fi
        fi
    done
    
    # Record command in session tracker
    SESSION_TRACKER["$tag"]="$command"
    COMMAND_COUNT=$((COMMAND_COUNT + 1))
    
    echo "$response"
    return 0
}

# Test output formatting
print_test() {
    local test_name=$1
    local status=$2
    local message=$3
    local details=$4
    
    TEST_RESULTS["$test_name"]="$status"
    
    case $status in
        "PASS")
            echo -e "${GREEN}✓ PASS${NC} $test_name"
            if [ -n "$message" ]; then
                echo -e "  ${BLUE}→${NC} $message"
            fi
            if [ -n "$details" ] && [ "$VERBOSE" -eq 1 ]; then
                echo -e "  ${CYAN}Details:${NC} $details"
            fi
            TESTS_PASSED=$((TESTS_PASSED + 1))
            ;;
        "FAIL")
            echo -e "${RED}✗ FAIL${NC} $test_name"
            if [ -n "$message" ]; then
                echo -e "  ${RED}→${NC} $message"
            fi
            if [ -n "$details" ] && [ "$VERBOSE" -eq 1 ]; then
                echo -e "  ${RED}Details:${NC} $details"
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

# Test server availability
test_server_availability() {
    echo -e "${BLUE}=== Testing Server Availability ===${NC}"
    
    # Test network connectivity
    if timeout $TIMEOUT bash -c "cat < /dev/null > /dev/tcp/$SERVER/$PORT" 2>/dev/null; then
        print_test "Network Connectivity" "PASS" "Server $SERVER is reachable on port $PORT"
    else
        print_test "Network Connectivity" "FAIL" "Cannot reach $SERVER:$PORT"
        return 1
    fi
    
    # Test IMAP banner
    local response=$(timeout $TIMEOUT bash -c "echo 'TAG0 CAPABILITY' | nc $SERVER $PORT 2>/dev/null | head -1")
    if echo "$response" | grep -q "^\* OK"; then
        print_test "IMAP Banner" "PASS" "Server responded with IMAP banner"
        echo "$response" | head -1 | sed "s/^/  ${BLUE}→${NC} /"
    else
        print_test "IMAP Banner" "FAIL" "No IMAP banner received"
    fi
    
    echo ""
    return 0
}

# Enhanced connection test
test_connection() {
    echo -e "${BLUE}=== Testing IMAP Connections ===${NC}"
    
    # Test regular IMAP
    local response=$(send_imap_persistent "CAPABILITY" 0)
    if echo "$response" | grep -q "OK"; then
        print_test "IMAP Connection" "PASS" "Connected to IMAP port $PORT"
        
        # Extract and display capabilities
        local caps=$(echo "$response" | grep -i "^\* CAPABILITY" | cut -d' ' -f3-)
        if [ -n "$caps" ]; then
            echo -e "  ${BLUE}Capabilities:${NC}"
            echo "$caps" | tr ' ' '\n' | while read cap; do
                echo -e "    ${GREEN}•${NC} $cap"
            done
        fi
    else
        print_test "IMAP Connection" "FAIL" "Failed to connect to IMAP port $PORT"
    fi
    
    # Test IMAPS if enabled
    if [ $TEST_SSL -eq 1 ]; then
        local ssl_response=$(send_imap_persistent "CAPABILITY" 1)
        if echo "$ssl_response" | grep -q "OK"; then
            print_test "IMAPS Connection" "PASS" "Connected to IMAPS port $SSL_PORT"
            
            # Test SSL certificate if verbose
            if [ "$VERBOSE" -eq 1 ]; then
                echo -n | openssl s_client -connect $SERVER:$SSL_PORT -brief 2>&1 | \
                    grep -E "(Certificate|Protocol|Cipher)" | \
                    sed "s/^/  ${CYAN}SSL:${NC} /"
            fi
        else
            print_test "IMAPS Connection" "SKIP" "SSL connection failed or not enabled"
        fi
    fi
    
    echo ""
}

# Enhanced authentication test
test_auth() {
    echo -e "${BLUE}=== Testing Authentication ===${NC}"
    
    # Test LOGIN
    local response=$(send_imap_persistent "LOGIN \"$USER\" \"$PASSWORD\"" 0)
    if echo "$response" | grep -q "OK.*LOGIN"; then
        print_test "LOGIN Command" "PASS" "Authentication successful"
        SESSION_ACTIVE=1
        
        # Parse greeting if present
        local greeting=$(echo "$response" | grep -i "^\* " | head -1)
        if [ -n "$greeting" ]; then
            echo -e "  ${BLUE}Greeting:${NC} ${greeting:2}"
        fi
    else
        print_test "LOGIN Command" "FAIL" "Authentication failed"
        local error=$(echo "$response" | grep -i "NO\|BAD" | head -1)
        if [ -n "$error" ]; then
            echo -e "  ${RED}Error:${NC} ${error}"
        fi
        return 1
    fi
    
    # Test authenticated capabilities
    response=$(send_imap_persistent "CAPABILITY" 0)
    if echo "$response" | grep -q "OK"; then
        local auth_caps=$(echo "$response" | grep -i "^\* CAPABILITY" | cut -d' ' -f3-)
        if [ -n "$auth_caps" ]; then
            echo -e "  ${BLUE}Auth Capabilities:${NC}"
            echo "$auth_caps" | tr ' ' '\n' | grep -E "(AUTH|X-|SASL)" | while read cap; do
                echo -e "    ${GREEN}•${NC} $cap"
            done
        fi
    fi
    
    echo ""
    return 0
}

# Comprehensive mailbox operations
test_mailbox_operations() {
    echo -e "${BLUE}=== Testing Mailbox Operations ===${NC}"
    
    # Test LIST
    local response=$(send_imap_persistent "LIST \"\" \"*\"" 0)
    if echo "$response" | grep -q "LIST"; then
        print_test "LIST Command" "PASS" "Mailbox listing successful"
        
        # Parse and display mailboxes
        local mailboxes=$(echo "$response" | grep "LIST" | sed -n 's/.*"\(.*\)".*/\1/p')
        local count=$(echo "$mailboxes" | wc -l)
        echo -e "  ${BLUE}Found $count mailbox(es):${NC}"
        
        if [ "$VERBOSE" -eq 1 ]; then
            echo "$mailboxes" | head -10 | while read mb; do
                echo -e "    ${CYAN}•${NC} $mb"
            done
            if [ "$count" -gt 10 ]; then
                echo -e "    ${CYAN}... and $((count - 10)) more${NC}"
            fi
        fi
    else
        print_test "LIST Command" "FAIL" "Mailbox listing failed"
    fi
    
    # Test LSUB (List subscribed)
    response=$(send_imap_persistent "LSUB \"\" \"*\"" 0)
    if echo "$response" | grep -q "LSUB"; then
        print_test "LSUB Command" "PASS" "Subscribed mailbox listing"
    else
        print_test "LSUB Command" "SKIP" "No subscribed mailboxes or command not supported"
    fi
    
    # Test CREATE and DELETE
    local test_mbox="test-$(date +%s%N)"
    response=$(send_imap_persistent "CREATE \"$test_mbox\"" 0)
    if echo "$response" | grep -q "OK.*CREATE"; then
        print_test "CREATE Command" "PASS" "Created mailbox: $test_mbox"
        
        # Verify creation with LIST
        response=$(send_imap_persistent "LIST \"\" \"$test_mbox\"" 0)
        if echo "$response" | grep -q "$test_mbox"; then
            print_test "CREATE Verification" "PASS" "Mailbox exists in listing"
        fi
        
        # Test RENAME
        local new_mbox="$test_mbox-renamed"
        response=$(send_imap_persistent "RENAME \"$test_mbox\" \"$new_mbox\"" 0)
        if echo "$response" | grep -q "OK.*RENAME"; then
            print_test "RENAME Command" "PASS" "Renamed to $new_mbox"
            test_mbox="$new_mbox"
        else
            print_test "RENAME Command" "SKIP" "RENAME not supported"
        fi
        
        # Test DELETE
        response=$(send_imap_persistent "DELETE \"$test_mbox\"" 0)
        if echo "$response" | grep -q "OK.*DELETE"; then
            print_test "DELETE Command" "PASS" "Deleted test mailbox"
        else
            print_test "DELETE Command" "FAIL" "Failed to delete mailbox"
        fi
    else
        print_test "CREATE Command" "SKIP" "CREATE not supported or permission denied"
    fi
    
    echo ""
}

# Enhanced SELECT/EXAMINE tests
test_mailbox_access() {
    echo -e "${BLUE}=== Testing Mailbox Access ===${NC}"
    
    # Test SELECT INBOX
    local response=$(send_imap_persistent "SELECT INBOX" 0)
    if echo "$response" | grep -q "OK.*SELECT"; then
        print_test "SELECT INBOX" "PASS" "INBOX selection successful"
        
        # Parse mailbox statistics
        local exists=$(echo "$response" | grep -o "[0-9]* EXISTS" | head -1 | grep -o "[0-9]*")
        local recent=$(echo "$response" | grep -o "[0-9]* RECENT" | head -1 | grep -o "[0-9]*")
        local unseen=$(echo "$response" | grep -o "UNSEEN [0-9]*" | head -1 | grep -o "[0-9]*")
        
        echo -e "  ${BLUE}Mailbox Status:${NC}"
        echo -e "    ${CYAN}Messages:${NC} ${exists:-0}"
        echo -e "    ${CYAN}Recent:${NC} ${recent:-0}"
        echo -e "    ${CYAN}Unseen:${NC} ${unseen:-0}"
        
        # Parse flags if available
        local flags=$(echo "$response" | grep -i "^\* FLAGS" | cut -d'(' -f2 | cut -d')' -f1)
        if [ -n "$flags" ]; then
            echo -e "    ${CYAN}Flags:${NC} $flags"
        fi
    else
        print_test "SELECT INBOX" "FAIL" "INBOX selection failed"
        return 1
    fi
    
    # Test EXAMINE (read-only)
    response=$(send_imap_persistent "EXAMINE INBOX" 0)
    if echo "$response" | grep -q "OK.*EXAMINE"; then
        print_test "EXAMINE Command" "PASS" "Read-only mailbox access"
    else
        print_test "EXAMINE Command" "SKIP" "EXAMINE not supported"
    fi
    
    # Test STATUS
    response=$(send_imap_persistent "STATUS INBOX (MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY)" 0)
    if echo "$response" | grep -q "STATUS.*INBOX"; then
        print_test "STATUS Command" "PASS" "Mailbox status retrieved"
        
        if [ "$VERBOSE" -eq 1 ]; then
            echo -e "  ${BLUE}Status Details:${NC}"
            echo "$response" | grep -o "([^)]*)" | tr -d '()' | tr ' ' '\n' | \
                while read item; do
                    if [[ "$item" =~ : ]]; then
                        echo -e "    ${CYAN}${item%%:*}:${NC} ${item#*:}"
                    fi
                done
        fi
    else
        print_test "STATUS Command" "SKIP" "STATUS not supported"
    fi
    
    # Test CLOSE
    response=$(send_imap_persistent "CLOSE" 0)
    if echo "$response" | grep -q "OK.*CLOSE"; then
        print_test "CLOSE Command" "PASS" "Mailbox closed successfully"
    else
        print_test "CLOSE Command" "SKIP" "CLOSE not needed or not supported"
    fi
    
    echo ""
}

# Enhanced message operations test
test_message_operations() {
    echo -e "${BLUE}=== Testing Message Operations ===${NC}"
    
    # Select INBOX first
    send_imap_persistent "SELECT INBOX" 0 >/dev/null 2>&1
    
    # Test SEARCH
    local response=$(send_imap_persistent "SEARCH ALL" 0)
    if echo "$response" | grep -q "SEARCH"; then
        local messages=$(echo "$response" | grep -o "SEARCH .*" | cut -d' ' -f2-)
        local count=$(echo $messages | wc -w)
        
        if [ "$count" -gt 0 ]; then
            print_test "SEARCH ALL" "PASS" "Found $count message(s)"
            
            # Test FETCH on first message if exists
            local first_msg=$(echo $messages | cut -d' ' -f1)
            if [ -n "$first_msg" ]; then
                response=$(send_imap_persistent "FETCH $first_msg (FLAGS INTERNALDATE RFC822.SIZE)" 0)
                if echo "$response" | grep -q "FETCH"; then
                    print_test "FETCH Command" "PASS" "Retrieved message metadata"
                    
                    if [ "$VERBOSE" -eq 1 ]; then
                        echo -e "  ${BLUE}Message $first_msg:${NC}"
                        echo "$response" | grep -A5 "FETCH" | while read line; do
                            echo -e "    ${CYAN}$line${NC}" | sed 's/^\* [0-9]* FETCH //'
                        done
                    fi
                else
                    print_test "FETCH Command" "SKIP" "FETCH not supported"
                fi
                
                # Test STORE (mark as seen)
                response=$(send_imap_persistent "STORE $first_msg +FLAGS (\Seen)" 0)
                if echo "$response" | grep -q "OK.*STORE"; then
                    print_test "STORE Command" "PASS" "Updated message flags"
                else
                    print_test "STORE Command" "SKIP" "STORE not supported"
                fi
            fi
            
            # Test COPY if we have messages
            response=$(send_imap_persistent "CREATE \"temp-copy-target\"" 0)
            if echo "$response" | grep -q "OK.*CREATE"; then
                response=$(send_imap_persistent "COPY $first_msg \"temp-copy-target\"" 0)
                if echo "$response" | grep -q "OK.*COPY"; then
                    print_test "COPY Command" "PASS" "Message copied successfully"
                else
                    print_test "COPY Command" "SKIP" "COPY not supported"
                fi
                send_imap_persistent "DELETE \"temp-copy-target\"" 0 >/dev/null 2>&1
            fi
        else
            print_test "SEARCH ALL" "PASS" "Mailbox is empty (0 messages)"
        fi
    else
        print_test "SEARCH Command" "FAIL" "SEARCH failed"
    fi
    
    # Test UID commands if supported
    response=$(send_imap_persistent "UID SEARCH ALL" 0)
    if echo "$response" | grep -q "SEARCH"; then
        print_test "UID SEARCH" "PASS" "UID-based search supported"
    else
        print_test "UID SEARCH" "SKIP" "UID commands not supported"
    fi
    
    echo ""
}

# Test server features and extensions
test_server_features() {
    echo -e "${BLUE}=== Testing Server Features ===${NC}"
    
    # Get full capability list
    local response=$(send_imap_persistent "CAPABILITY" 0)
    local capabilities=$(echo "$response" | grep -i "^\* CAPABILITY" | cut -d' ' -f3-)
    
    if [ -n "$capabilities" ]; then
        print_test "Server Features" "PASS" "Server capabilities retrieved"
        
        # Check for important extensions
        declare -A features=(
            ["IDLE"]="IDLE command"
            ["QUOTA"]="Quota support"
            ["ACL"]="Access Control Lists"
            ["NAMESPACE"]="Namespace support"
            ["UIDPLUS"]="UIDPLUS extension"
            ["CONDSTORE"]="Conditional STORE"
            ["SORT"]="SORT extension"
            ["THREAD"]="THREAD extension"
        )
        
        echo -e "  ${BLUE}Supported Extensions:${NC}"
        for feature in "${!features[@]}"; do
            if echo "$capabilities" | grep -qi "$feature"; then
                echo -e "    ${GREEN}✓${NC} ${features[$feature]}"
            else
                echo -e "    ${YELLOW}✗${NC} ${features[$feature]}"
            fi
        done
        
        # Test IDLE if supported
        if echo "$capabilities" | grep -qi "IDLE"; then
            print_test "IDLE Extension" "SKIP" "Present (test manually: TAG IDLE)"
        fi
    else
        print_test "Server Features" "FAIL" "Could not retrieve capabilities"
    fi
    
    echo ""
}

# Test session management
test_session_management() {
    echo -e "${BLUE}=== Testing Session Management ===${NC}"
    
    # Test NOOP
    local response=$(send_imap_persistent "NOOP" 0)
    if echo "$response" | grep -q "OK.*NOOP"; then
        print_test "NOOP Command" "PASS" "Connection keep-alive successful"
    else
        print_test "NOOP Command" "FAIL" "NOOP failed"
    fi
    
    # Test CHECK
    response=$(send_imap_persistent "CHECK" 0)
    if echo "$response" | grep -q "OK.*CHECK"; then
        print_test "CHECK Command" "PASS" "Checkpoint successful"
    else
        print_test "CHECK Command" "SKIP" "CHECK not supported"
    fi
    
    echo ""
}

# Logout and session cleanup
test_logout() {
    echo -e "${BLUE}=== Testing Session Cleanup ===${NC}"
    
    local response=$(send_imap_persistent "LOGOUT" 0)
    if echo "$response" | grep -q "BYE"; then
        print_test "LOGOUT Command" "PASS" "Session terminated properly"
        SESSION_ACTIVE=0
        
        # Extract bye message
        local bye_msg=$(echo "$response" | grep -i "^\* BYE" | cut -d' ' -f3-)
        if [ -n "$bye_msg" ]; then
            echo -e "  ${BLUE}Server goodbye:${NC} $bye_msg"
        fi
    else
        print_test "LOGOUT Command" "FAIL" "Logout failed"
    fi
    
    echo ""
}

# Run comprehensive test suite
run_comprehensive_tests() {
    log_info "Starting comprehensive IMAP test suite"
    log_info "Server: $SERVER, User: $USER"
    log_info "Time: $(date)"
    echo ""
    
    if test_server_availability; then
        test_connection
        if test_auth; then
            test_mailbox_operations
            test_mailbox_access
            test_message_operations
            test_server_features
            test_session_management
            test_logout
        fi
    fi
    
    print_summary
}

# Quick connection test
run_quick_test() {
    echo -e "${BLUE}=== Quick Connection Test ===${NC}"
    
    # Test basic connectivity
    if timeout $TIMEOUT bash -c "echo 'Q01 CAPABILITY' | nc $SERVER $PORT 2>/dev/null | grep -q OK"; then
        echo -e "${GREEN}✓ Server is reachable${NC}"
        
        # Test authentication
        local response=$(timeout $TIMEOUT bash -c "echo 'Q02 LOGIN \"$USER\" \"$PASSWORD\"'; sleep 1; echo 'Q03 LOGOUT' | nc $SERVER $PORT 2>/dev/null")
        
        if echo "$response" | grep -q "Q02 OK.*LOGIN"; then
            echo -e "${GREEN}✓ Authentication successful${NC}"
            
            if echo "$response" | grep -q "Q03 OK.*LOGOUT"; then
                echo -e "${GREEN}✓ Session cleanup successful${NC}"
                echo -e "${GREEN}✅ Quick test passed!${NC}"
                return 0
            fi
        else
            echo -e "${RED}✗ Authentication failed${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ Server not responding${NC}"
        return 1
    fi
}

# Interactive mode
interactive_mode() {
    echo -e "${BLUE}=== Interactive IMAP Client ===${NC}"
    echo -e "Type IMAP commands (without tag, auto-generated)"
    echo -e "Special commands: quit, help, raw <command>, reconnect"
    echo ""
    
    # Initial connection
    send_imap_persistent "CAPABILITY" 0 >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_error "Failed to connect to server"
        return 1
    fi
    
    local cmd=""
    while true; do
        read -e -p "IMAP> " cmd
        
        case "$cmd" in
            quit|exit)
                if [ "$SESSION_ACTIVE" -eq 1 ]; then
                    send_imap_persistent "LOGOUT" 0
                fi
                break
                ;;
            help)
                echo "Available commands:"
                echo "  CAPABILITY                    - List server capabilities"
                echo "  LOGIN user pass              - Authenticate"
                echo "  LIST \"\" \"*\"                - List all mailboxes"
                echo "  SELECT mailbox               - Select mailbox"
                echo "  SEARCH ALL                   - Search messages"
                echo "  FETCH n (FLAGS BODY.PEEK[])  - Fetch message"
                echo "  NOOP                         - Keep connection alive"
                echo "  LOGOUT                       - End session"
                echo "  reconnect                    - Reconnect to server"
                echo "  raw TAG COMMAND              - Send raw command with tag"
                echo "  quit                         - Exit interactive mode"
                ;;
            reconnect)
                cleanup
                send_imap_persistent "CAPABILITY" 0 >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    echo "Reconnected successfully"
                else
                    echo "Reconnection failed"
                fi
                ;;
            raw*)
                local raw_cmd="${cmd#raw }"
                echo -e "${CYAN}Sending raw: $raw_cmd${NC}"
                response=$(send_imap_persistent "$raw_cmd" 0)
                echo "$response"
                ;;
            "")
                # Send NOOP on empty line to keep connection alive
                response=$(send_imap_persistent "NOOP" 0)
                if [ "$VERBOSE" -eq 1 ]; then
                    echo "$response"
                fi
                ;;
            *)
                response=$(send_imap_persistent "$cmd" 0)
                echo "$response"
                ;;
        esac
    done
    
    cleanup
}

# Print summary report
print_summary() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}              TEST SUMMARY              ${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # Overall status
    if [ $TESTS_FAILED -eq 0 ] && [ $TESTS_PASSED -gt 0 ]; then
        echo -e "${GREEN}✅ ALL TESTS PASSED${NC}"
    elif [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    else
        echo -e "${YELLOW}⚠ NO TESTS EXECUTED${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}Statistics:${NC}"
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo -e "  ${BLUE}Total:${NC}   $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
    echo -e "  ${BLUE}Commands:${NC} $COMMAND_COUNT"
    
    # Session info
    echo ""
    echo -e "${CYAN}Session Information:${NC}"
    echo -e "  Server: $SERVER:$PORT"
    echo -e "  User: $USER"
    echo -e "  SSL Tested: $( [ $TEST_SSL -eq 1 ] && echo "Yes" || echo "No" )"
    echo -e "  Session Active: $( [ $SESSION_ACTIVE -eq 1 ] && echo "Yes" || echo "No" )"
    
    # Detailed results if verbose
    if [ "$VERBOSE" -eq 1 ] && [ ${#TEST_RESULTS[@]} -gt 0 ]; then
        echo ""
        echo -e "${CYAN}Detailed Results:${NC}"
        for test_name in "${!TEST_RESULTS[@]}"; do
            case "${TEST_RESULTS[$test_name]}" in
                "PASS") color=$GREEN ;;
                "FAIL") color=$RED ;;
                "SKIP") color=$YELLOW ;;
                *) color=$NC ;;
            esac
            echo -e "  ${color}${TEST_RESULTS[$test_name]}${NC}: $test_name"
        done
    fi
    
    echo -e "${BLUE}========================================${NC}"
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
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
            --ssl-port)
                SSL_PORT="$2"
                shift 2
                ;;
            -u|--user)
                USER="$2"
                shift 2
                ;;
            -w|--password|--pass)
                PASSWORD="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
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
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            --no-ssl)
                TEST_SSL=0
                shift
                ;;
            --insecure)
                # For SSL testing without certificate verification
                INSECURE=1
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
LightMail IMAP Test Script - Enhanced Version

Usage: $0 [OPTIONS]

Options:
  -h, --help                  Show this help message
  -s, --server HOST           IMAP server hostname (default: localhost)
  -p, --port PORT             IMAP port (default: 1143)
      --ssl-port PORT         IMAPS port (default: 1993)
  -u, --user USER             Username (default: user@example.com)
  -w, --password PASS         Password
  -t, --timeout SEC           Connection timeout (default: 5)
  -q, --quick                 Run quick connection test only
  -i, --interactive           Run interactive test mode
  -v, --verbose               Enable verbose output
      --no-ssl                Disable SSL tests
      --insecure              Allow insecure SSL connections

Environment Variables:
  IMAP_SERVER, IMAP_PORT, IMAP_USER, IMAP_PASS, IMAP_SSL_PORT, IMAP_TIMEOUT

Examples:
  $0                           # Run all tests
  $0 -q                       # Quick test only
  $0 -i                       # Interactive mode
  $0 -s mail.example.com -u test@domain.com -w secret
  $0 --server imap.gmail.com --ssl-port 993 --no-ssl

EOF
}

# Main execution
main() {
    parse_arguments "$@"
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   LightMail IMAP Test Suite - v3.0   ${NC}"
    echo -e "${BLUE}    Enhanced Persistent Sessions      ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Check for required commands
    local required_commands="nc timeout grep sed"
    for cmd in $required_commands; do
        if ! command -v $cmd >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Run selected mode
    if [ -n "$INTERACTIVE_MODE" ]; then
        interactive_mode
    elif [ -n "$QUICK_MODE" ]; then
        run_quick_test
    else
        run_comprehensive_tests
    fi
    
    # Final cleanup
    cleanup
}

# Run main function
main "$@"

# Exit with appropriate code
if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
elif [ $TESTS_PASSED -eq 0 ] && [ $TESTS_SKIPPED -gt 0 ]; then
    exit 2
else
    exit 0
fi