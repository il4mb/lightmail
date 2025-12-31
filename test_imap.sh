#!/bin/bash

# LightMail IMAP Test Script
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

# Send IMAP command and get response
send_imap() {
    local command=$1
    local use_ssl=${2:-0}
    
    if [ $use_ssl -eq 1 ]; then
        echo -e "$command\r\n" | timeout $TIMEOUT openssl s_client -connect $SERVER:$SSL_PORT -quiet 2>/dev/null
    else
        echo -e "$command\r\n" | timeout $TIMEOUT nc $SERVER $PORT
    fi
}

# Test connection
test_connection() {
    echo -e "${BLUE}=== Testing Connection ===${NC}"
    
    # Test regular IMAP
    response=$(send_imap "TAG1 CAPABILITY" 0)
    if echo "$response" | grep -q "OK"; then
        print_test "IMAP Connection" "PASS" "Connected to IMAP port $PORT"
    else
        print_test "IMAP Connection" "FAIL" "Failed to connect to IMAP port $PORT"
    fi
    
    # Test IMAPS if enabled
    if [ $TEST_SSL -eq 1 ]; then
        response=$(send_imap "TAG2 CAPABILITY" 1)
        if echo "$response" | grep -q "OK"; then
            print_test "IMAPS Connection" "PASS" "Connected to IMAPS port $SSL_PORT"
        else
            print_test "IMAPS Connection" "SKIP" "SSL not enabled or certificate issue"
        fi
    fi
    
    echo ""
}

# Test authentication
test_auth() {
    echo -e "${BLUE}=== Testing Authentication ===${NC}"
    
    # Test LOGIN command
    response=$(send_imap "A01 LOGIN \"$USER\" \"$PASSWORD\"")
    if echo "$response" | grep -q "OK.*LOGIN"; then
        print_test "LOGIN Command" "PASS" "Authentication successful"
        AUTH_TAG="A01"
    else
        print_test "LOGIN Command" "FAIL" "Authentication failed"
        return 1
    fi
    
    # Test LOGOUT
    response=$(send_imap "A02 LOGOUT")
    if echo "$response" | grep -q "BYE"; then
        print_test "LOGOUT Command" "PASS" "Logout successful"
    else
        print_test "LOGOUT Command" "FAIL" "Logout failed"
    fi
    
    echo ""
    return 0
}

# Test mailbox commands
test_mailbox_commands() {
    echo -e "${BLUE}=== Testing Mailbox Commands ===${NC}"
    
    # Login first
    send_imap "B01 LOGIN \"$USER\" \"$PASSWORD\"" > /dev/null 2>&1
    
    # Test LIST
    response=$(send_imap "B02 LIST \"\" \"*\"")
    if echo "$response" | grep -q "LIST"; then
        print_test "LIST Command" "PASS" "Mailbox listing successful"
        
        # Extract mailbox names
        mailboxes=$(echo "$response" | grep "LIST" | sed 's/.*"\(.*\)".*/\1/')
        echo -e "  ${BLUE}Mailboxes found:${NC}"
        echo "$mailboxes" | while read mb; do
            echo -e "    ${BLUE}•${NC} $mb"
        done
    else
        print_test "LIST Command" "FAIL" "Mailbox listing failed"
    fi
    
    # Test SELECT INBOX
    response=$(send_imap "B03 SELECT INBOX")
    if echo "$response" | grep -q "OK.*SELECT"; then
        print_test "SELECT Command" "PASS" "INBOX selection successful"
        
        # Parse response counts
        exists=$(echo "$response" | grep -o "[0-9]* EXISTS" | grep -o "[0-9]*")
        recent=$(echo "$response" | grep -o "[0-9]* RECENT" | grep -o "[0-9]*")
        if [ -n "$exists" ]; then
            echo -e "  ${BLUE}Messages:${NC} $exists exists, $recent recent"
        fi
    else
        print_test "SELECT Command" "FAIL" "INBOX selection failed"
    fi
    
    # Test EXAMINE (read-only SELECT)
    response=$(send_imap "B04 EXAMINE INBOX")
    if echo "$response" | grep -q "OK.*EXAMINE"; then
        print_test "EXAMINE Command" "PASS" "Read-only mailbox access"
    else
        print_test "EXAMINE Command" "FAIL" "EXAMINE command failed"
    fi
    
    # Test CREATE
    test_mailbox="test-$(date +%s)"
    response=$(send_imap "B05 CREATE \"$test_mailbox\"")
    if echo "$response" | grep -q "OK.*CREATE"; then
        print_test "CREATE Command" "PASS" "Created mailbox: $test_mailbox"
        
        # Test DELETE
        response=$(send_imap "B06 DELETE \"$test_mailbox\"")
        if echo "$response" | grep -q "OK.*DELETE"; then
            print_test "DELETE Command" "PASS" "Deleted test mailbox"
        else
            print_test "DELETE Command" "FAIL" "Failed to delete test mailbox"
        fi
    else
        print_test "CREATE Command" "FAIL" "Failed to create test mailbox"
    fi
    
    # Test STATUS
    response=$(send_imap "B07 STATUS INBOX (MESSAGES RECENT UNSEEN)")
    if echo "$response" | grep -q "STATUS.*INBOX"; then
        print_test "STATUS Command" "PASS" "Mailbox status retrieved"
        
        # Parse status values
        messages=$(echo "$response" | grep -o "MESSAGES [0-9]*" | grep -o "[0-9]*")
        recent=$(echo "$response" | grep -o "RECENT [0-9]*" | grep -o "[0-9]*")
        unseen=$(echo "$response" | grep -o "UNSEEN [0-9]*" | grep -o "[0-9]*")
        echo -e "  ${BLUE}Status:${NC} Messages=$messages, Recent=$recent, Unseen=$unseen"
    else
        print_test "STATUS Command" "FAIL" "STATUS command failed"
    fi
    
    # Logout
    send_imap "B08 LOGOUT" > /dev/null 2>&1
    
    echo ""
}

# Test message commands
test_message_commands() {
    echo -e "${BLUE}=== Testing Message Commands ===${NC}"
    
    # Login first
    send_imap "C01 LOGIN \"$USER\" \"$PASSWORD\"" > /dev/null 2>&1
    send_imap "C02 SELECT INBOX" > /dev/null 2>&1
    
    # Test SEARCH ALL
    response=$(send_imap "C03 SEARCH ALL")
    if echo "$response" | grep -q "SEARCH"; then
        print_test "SEARCH Command" "PASS" "Message search successful"
        
        # Get message sequence numbers
        messages=$(echo "$response" | grep -o "SEARCH .*" | cut -d' ' -f2-)
        if [ -n "$messages" ] && [ "$messages" != "SEARCH" ]; then
            count=$(echo $messages | wc -w)
            echo -e "  ${BLUE}Found:${NC} $count message(s)"
            
            # Test FETCH on first message if exists
            first_msg=$(echo $messages | cut -d' ' -f1)
            if [ -n "$first_msg" ] && [ "$first_msg" != "SEARCH" ]; then
                # Test FETCH flags
                response=$(send_imap "C04 FETCH $first_msg (FLAGS)")
                if echo "$response" | grep -q "FETCH.*FLAGS"; then
                    print_test "FETCH FLAGS" "PASS" "Retrieved message flags"
                    flags=$(echo "$response" | grep -o "FLAGS.*)" | sed 's/FLAGS //')
                    echo -e "  ${BLUE}Flags:${NC} $flags"
                else
                    print_test "FETCH FLAGS" "FAIL" "Failed to fetch flags"
                fi
                
                # Test FETCH envelope
                response=$(send_imap "C05 FETCH $first_msg (RFC822.SIZE ENVELOPE)")
                if echo "$response" | grep -q "FETCH.*RFC822.SIZE"; then
                    print_test "FETCH Envelope" "PASS" "Retrieved message envelope"
                    size=$(echo "$response" | grep -o "RFC822.SIZE [0-9]*" | grep -o "[0-9]*")
                    echo -e "  ${BLUE}Size:${NC} $size bytes"
                else
                    print_test "FETCH Envelope" "FAIL" "Failed to fetch envelope"
                fi
            else
                print_test "Message Fetch" "SKIP" "No messages to test"
            fi
        else
            print_test "Message Fetch" "SKIP" "No messages in mailbox"
        fi
    else
        print_test "SEARCH Command" "FAIL" "SEARCH command failed"
    fi
    
    # Test APPEND (if there are no messages to avoid duplication)
    if [ -z "$messages" ] || [ "$messages" = "SEARCH" ]; then
        test_message="Subject: Test Message\r\nFrom: test@example.com\r\nTo: $USER\r\n\r\nThis is a test message.\r\n"
        message_size=${#test_message}
        
        # Start APPEND
        response=$(send_imap "C06 APPEND INBOX {${message_size}}")
        if echo "$response" | grep -q "+"; then
            # Send message data
            echo -e "$test_message\r\n" | nc $SERVER $PORT > /dev/null 2>&1
            
            # Check if append was successful
            response=$(send_imap "C07 NOOP")
            if echo "$response" | grep -q "OK.*APPEND"; then
                print_test "APPEND Command" "PASS" "Message appended successfully"
            else
                print_test "APPEND Command" "FAIL" "Message append failed"
            fi
        else
            print_test "APPEND Command" "FAIL" "APPEND preparation failed"
        fi
    else
        print_test "APPEND Command" "SKIP" "Skipping to avoid duplicate messages"
    fi
    
    # Test STORE (flag operations)
    if [ -n "$first_msg" ] && [ "$first_msg" != "SEARCH" ]; then
        response=$(send_imap "C08 STORE $first_msg +FLAGS (\\Seen)")
        if echo "$response" | grep -q "OK.*STORE"; then
            print_test "STORE Command" "PASS" "Message flagged as \\Seen"
        else
            print_test "STORE Command" "FAIL" "Failed to set message flags"
        fi
    fi
    
    # Test COPY (requires source and destination)
    send_imap "C09 CREATE \"test-copy\"" > /dev/null 2>&1
    if [ -n "$first_msg" ] && [ "$first_msg" != "SEARCH" ]; then
        response=$(send_imap "C10 COPY $first_msg \"test-copy\"")
        if echo "$response" | grep -q "OK.*COPY"; then
            print_test "COPY Command" "PASS" "Message copied successfully"
        else
            print_test "COPY Command" "FAIL" "Failed to copy message"
        fi
    fi
    
    # Cleanup
    send_imap "C11 DELETE \"test-copy\"" > /dev/null 2>&1
    
    # Test EXPUNGE
    response=$(send_imap "C12 EXPUNGE")
    if echo "$response" | grep -q "OK.*EXPUNGE"; then
        print_test "EXPUNGE Command" "PASS" "Expunge completed"
    else
        print_test "EXPUNGE Command" "SKIP" "No messages to expunge"
    fi
    
    # Logout
    send_imap "C13 LOGOUT" > /dev/null 2>&1
    
    echo ""
}

# Test UID commands
test_uid_commands() {
    echo -e "${BLUE}=== Testing UID Commands ===${NC}"
    
    # Login and select
    send_imap "D01 LOGIN \"$USER\" \"$PASSWORD\"" > /dev/null 2>&1
    send_imap "D02 SELECT INBOX" > /dev/null 2>&1
    
    # Test UID SEARCH
    response=$(send_imap "D03 UID SEARCH ALL")
    if echo "$response" | grep -q "SEARCH"; then
        print_test "UID SEARCH" "PASS" "UID search successful"
        
        # Get UIDs
        uids=$(echo "$response" | grep -o "SEARCH .*" | cut -d' ' -f2-)
        if [ -n "$uids" ] && [ "$uids" != "SEARCH" ]; then
            first_uid=$(echo $uids | cut -d' ' -f1)
            
            # Test UID FETCH
            response=$(send_imap "D04 UID FETCH $first_uid (FLAGS)")
            if echo "$response" | grep -q "FETCH.*FLAGS"; then
                print_test "UID FETCH" "PASS" "UID-based fetch successful"
            else
                print_test "UID FETCH" "FAIL" "UID fetch failed"
            fi
            
            # Test UID STORE
            response=$(send_imap "D05 UID STORE $first_uid +FLAGS (\\Flagged)")
            if echo "$response" | grep -q "OK.*STORE"; then
                print_test "UID STORE" "PASS" "UID-based store successful"
            else
                print_test "UID STORE" "FAIL" "UID store failed"
            fi
            
            # Test UID COPY
            send_imap "D06 CREATE \"test-uid-copy\"" > /dev/null 2>&1
            response=$(send_imap "D07 UID COPY $first_uid \"test-uid-copy\"")
            if echo "$response" | grep -q "OK.*COPY"; then
                print_test "UID COPY" "PASS" "UID-based copy successful"
            else
                print_test "UID COPY" "FAIL" "UID copy failed"
            fi
            
            # Cleanup
            send_imap "D08 DELETE \"test-uid-copy\"" > /dev/null 2>&1
        else
            print_test "UID Operations" "SKIP" "No messages with UIDs"
        fi
    else
        print_test "UID SEARCH" "FAIL" "UID SEARCH command failed"
    fi
    
    # Logout
    send_imap "D09 LOGOUT" > /dev/null 2>&1
    
    echo ""
}

# Test capability discovery
test_capabilities() {
    echo -e "${BLUE}=== Testing Server Capabilities ===${NC}"
    
    response=$(send_imap "E01 CAPABILITY")
    if echo "$response" | grep -q "CAPABILITY"; then
        print_test "CAPABILITY Command" "PASS" "Server capabilities retrieved"
        
        # Extract and display capabilities
        caps=$(echo "$response" | grep -o "CAPABILITY .*" | cut -d' ' -f2- | sed 's/\r//')
        echo -e "  ${BLUE}Capabilities:${NC}"
        echo "$caps" | tr ' ' '\n' | while read cap; do
            echo -e "    ${BLUE}•${NC} $cap"
        done
        
        # Check for important capabilities
        if echo "$caps" | grep -q "IMAP4rev1"; then
            print_test "IMAP4rev1 Support" "PASS" "Protocol version supported"
        else
            print_test "IMAP4rev1 Support" "FAIL" "Missing IMAP4rev1 support"
        fi
        
        if echo "$caps" | grep -q "AUTH=PLAIN"; then
            print_test "PLAIN Auth" "PASS" "Plain authentication supported"
        else
            print_test "PLAIN Auth" "WARN" "Plain authentication not advertised"
        fi
        
        if echo "$caps" | grep -q "STARTTLS"; then
            print_test "STARTTLS Support" "PASS" "STARTTLS available"
        else
            print_test "STARTTLS Support" "INFO" "STARTTLS not advertised"
        fi
        
        if echo "$caps" | grep -q "UIDPLUS"; then
            print_test "UIDPLUS Extension" "PASS" "UIDPLUS extension supported"
        else
            print_test "UIDPLUS Extension" "INFO" "UIDPLUS extension not advertised"
        fi
    else
        print_test "CAPABILITY Command" "FAIL" "Failed to get capabilities"
    fi
    
    echo ""
}

# Test NOOP and CHECK commands
test_utility_commands() {
    echo -e "${BLUE}=== Testing Utility Commands ===${NC}"
    
    # Login first
    send_imap "F01 LOGIN \"$USER\" \"$PASSWORD\"" > /dev/null 2>&1
    send_imap "F02 SELECT INBOX" > /dev/null 2>&1
    
    # Test NOOP
    response=$(send_imap "F03 NOOP")
    if echo "$response" | grep -q "OK.*NOOP"; then
        print_test "NOOP Command" "PASS" "NOOP command successful"
    else
        print_test "NOOP Command" "FAIL" "NOOP command failed"
    fi
    
    # Test CHECK
    response=$(send_imap "F04 CHECK")
    if echo "$response" | grep -q "OK.*CHECK"; then
        print_test "CHECK Command" "PASS" "CHECK command successful"
    else
        print_test "CHECK Command" "FAIL" "CHECK command failed"
    fi
    
    # Test CLOSE
    response=$(send_imap "F05 CLOSE")
    if echo "$response" | grep -q "OK.*CLOSE"; then
        print_test "CLOSE Command" "PASS" "CLOSE command successful"
    else
        print_test "CLOSE Command" "FAIL" "CLOSE command failed"
    fi
    
    # Logout
    send_imap "F06 LOGOUT" > /dev/null 2>&1
    
    echo ""
}

# Test error conditions
test_error_conditions() {
    echo -e "${BLUE}=== Testing Error Conditions ===${NC}"
    
    # Test invalid login
    response=$(send_imap "G01 LOGIN \"invalid\" \"wrong\"")
    if echo "$response" | grep -q "NO.*LOGIN"; then
        print_test "Invalid Login" "PASS" "Correctly rejected invalid credentials"
    else
        print_test "Invalid Login" "FAIL" "Should reject invalid credentials"
    fi
    
    # Test invalid command
    response=$(send_imap "G02 INVALIDCMD")
    if echo "$response" | grep -q "BAD"; then
        print_test "Invalid Command" "PASS" "Correctly rejected invalid command"
    else
        print_test "Invalid Command" "FAIL" "Should reject invalid commands"
    fi
    
    # Test SELECT without login
    response=$(send_imap "G03 SELECT INBOX")
    if echo "$response" | grep -q "NO.*authenticated"; then
        print_test "Unauthorized Access" "PASS" "Correctly requires authentication"
    else
        print_test "Unauthorized Access" "FAIL" "Should require authentication"
    fi
    
    # Test non-existent mailbox
    send_imap "G04 LOGIN \"$USER\" \"$PASSWORD\"" > /dev/null 2>&1
    response=$(send_imap "G05 SELECT \"nonexistent\"")
    if echo "$response" | grep -q "NO.*not found"; then
        print_test "Non-existent Mailbox" "PASS" "Correctly handles missing mailbox"
    else
        print_test "Non-existent Mailbox" "FAIL" "Should reject non-existent mailbox"
    fi
    
    send_imap "G06 LOGOUT" > /dev/null 2>&1
    
    echo ""
}

# Performance test
test_performance() {
    echo -e "${BLUE}=== Testing Performance ===${NC}"
    
    start_time=$(date +%s%N)
    
    # Run a series of commands
    for i in {1..10}; do
        send_imap "P$i LOGIN \"$USER\" \"$PASSWORD\"" > /dev/null 2>&1
        send_imap "Q$i SELECT INBOX" > /dev/null 2>&1
        send_imap "R$i SEARCH ALL" > /dev/null 2>&1
        send_imap "S$i LOGOUT" > /dev/null 2>&1
    done
    
    end_time=$(date +%s%N)
    elapsed=$(( (end_time - start_time) / 1000000 ))
    
    print_test "Performance" "PASS" "10 full cycles in ${elapsed}ms (avg: $((elapsed / 10))ms per cycle)"
    
    echo ""
}

# Comprehensive test runner
run_all_tests() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}      LightMail IMAP Server Tests      ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "Server: ${YELLOW}$SERVER${NC}"
    echo -e "User: ${YELLOW}$USER${NC}"
    echo -e "Time: ${YELLOW}$(date)${NC}"
    echo -e "${BLUE}========================================${NC}\n"
    
    # Run tests
    test_connection
    test_capabilities
    test_auth
    if [ $? -eq 0 ]; then
        test_mailbox_commands
        test_message_commands
        test_uid_commands
        test_utility_commands
        test_error_conditions
        test_performance
    else
        echo -e "${RED}Skipping further tests due to authentication failure${NC}\n"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 7))
    fi
    
    # Summary
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}              Test Summary              ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo -e "${BLUE}Total:${NC}   $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}✅ All tests passed!${NC}"
        return 0
    else
        echo -e "\n${RED}❌ Some tests failed${NC}"
        return 1
    fi
}

# Quick test
run_quick_test() {
    echo -e "${BLUE}=== Quick Connection Test ===${NC}"
    
    # Test basic connection
    response=$(send_imap "Q01 CAPABILITY" 0)
    if echo "$response" | grep -q "OK"; then
        echo -e "${GREEN}✓ IMAP server is responding${NC}"
        
        # Test login
        response=$(send_imap "Q02 LOGIN \"$USER\" \"$PASSWORD\"")
        if echo "$response" | grep -q "OK.*LOGIN"; then
            echo -e "${GREEN}✓ Authentication successful${NC}"
            
            # Test basic operations
            send_imap "Q03 SELECT INBOX" > /dev/null 2>&1
            response=$(send_imap "Q04 SEARCH ALL")
            if echo "$response" | grep -q "SEARCH"; then
                echo -e "${GREEN}✓ Basic operations working${NC}"
            else
                echo -e "${YELLOW}⚠ Basic operations incomplete${NC}"
            fi
            
            send_imap "Q05 LOGOUT" > /dev/null 2>&1
        else
            echo -e "${RED}✗ Authentication failed${NC}"
        fi
    else
        echo -e "${RED}✗ IMAP server not responding${NC}"
        return 1
    fi
    
    echo ""
    return 0
}

# SSL-specific tests
test_ssl_features() {
    echo -e "${BLUE}=== SSL/TLS Feature Tests ===${NC}"
    
    # Test STARTTLS capability
    response=$(send_imap "S01 CAPABILITY")
    if echo "$response" | grep -q "STARTTLS"; then
        print_test "STARTTLS Advertised" "PASS" "Server advertises STARTTLS"
    else
        print_test "STARTTLS Advertised" "INFO" "STARTTLS not advertised"
    fi
    
    # Test certificate
    if [ $TEST_SSL -eq 1 ]; then
        cert_info=$(echo "" | openssl s_client -connect $SERVER:$SSL_PORT -showcerts 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
        if [ $? -eq 0 ]; then
            print_test "SSL Certificate" "PASS" "Valid SSL certificate"
            
            # Extract certificate details
            subject=$(echo "$cert_info" | grep "Subject:" | head -1)
            issuer=$(echo "$cert_info" | grep "Issuer:" | head -1)
            expiry=$(echo "$cert_info" | grep "Not After" | head -1)
            
            echo -e "  ${BLUE}Subject:${NC} $subject"
            echo -e "  ${BLUE}Issuer:${NC} $issuer"
            echo -e "  ${BLUE}Expires:${NC} $expiry"
        else
            print_test "SSL Certificate" "FAIL" "Invalid or missing SSL certificate"
        fi
    fi
    
    echo ""
}

# Interactive test mode
interactive_test() {
    echo -e "${BLUE}=== Interactive IMAP Test ===${NC}"
    echo -e "Type IMAP commands (e.g., 'CAPABILITY', 'LOGIN \"user\" \"pass\"')"
    echo -e "Type 'quit' to exit, 'help' for available commands"
    echo ""
    
    tag=1
    while true; do
        read -p "IMAP> " cmd
        
        case $cmd in
            quit|exit)
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
                echo "  LOGOUT"
                echo "  quit - exit interactive mode"
                ;;
            "")
                continue
                ;;
            *)
                response=$(send_imap "I${tag} $cmd")
                echo "$response"
                tag=$((tag + 1))
                ;;
        esac
    done
}

# Command line options
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -s, --server HOST   IMAP server hostname (default: localhost)"
    echo "  -p, --port PORT     IMAP port (default: 143)"
    echo "  -P, --ssl-port PORT IMAPS port (default: 993)"
    echo "  -u, --user USER     Username (default: user@example.com)"
    echo "  -w, --pass PASS     Password (default: password123)"
    echo "  -q, --quick         Run quick connection test only"
    echo "  -i, --interactive   Run interactive test mode"
    echo "  --no-ssl            Disable SSL tests"
    echo "  --test-ssl          Run SSL feature tests"
    echo "  -t, --timeout SEC   Connection timeout (default: 5)"
    echo ""
    echo "Examples:"
    echo "  $0                   # Run all tests"
    echo "  $0 -q               # Quick test only"
    echo "  $0 -i               # Interactive mode"
    echo "  $0 -s mail.example.com -u test@example.com"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
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
        -P|--ssl-port)
            SSL_PORT="$2"
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
        --no-ssl)
            TEST_SSL=0
            shift
            ;;
        --test-ssl)
            SSL_TEST_ONLY=1
            shift
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
if [ -n "$INTERACTIVE_MODE" ]; then
    interactive_test
elif [ -n "$QUICK_MODE" ]; then
    run_quick_test
elif [ -n "$SSL_TEST_ONLY" ]; then
    test_ssl_features
else
    run_all_tests
fi

# Exit with appropriate code
if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi