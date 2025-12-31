#!/usr/bin/env bash
set -euo pipefail

echo "Building tests..."
mkdir -p build/tests

gcc -I. -Iinclude -o build/tests/test_parse_command tests/test_parse_command.c src/imap/imap-send.c -lssl -lcrypto -lpthread
gcc -I. -Iinclude -o build/tests/test_hash_password tests/test_hash_password.c src/core/auth.c -lcrypto
gcc -I. -Iinclude -o build/tests/test_s3_key tests/test_s3_key.c tests/test_s3_key_stub.c tests/test_stubs.c -lcurl -lcrypto
gcc -Iinclude -o build/tests/test_logger tests/test_logger.c src/log/log.c src/core/config.c -lpthread
gcc -I. -Iinclude -o build/tests/test_metrics tests/test_metrics.c src/metrics/metrics.c src/log/log.c src/core/config.c -lpthread
gcc -I. -Iinclude -o build/tests/test_lmtp_queue tests/test_lmtp_queue.c src/lmtp/queue.c src/metrics/metrics.c src/log/log.c src/core/config.c -lpthread
gcc -I. -Iinclude -o build/tests/test_lmtp_worker_db tests/test_lmtp_worker_db.c src/lmtp/queue.c src/metrics/metrics.c src/log/log.c src/core/config.c -lpthread
gcc -I. -Iinclude -o build/tests/test_memory_sampler tests/test_memory_sampler.c src/metrics/memory_sampler.c src/metrics/metrics.c src/log/log.c src/core/config.c -lpthread

echo "Running tests..."
./build/tests/test_parse_command
./build/tests/test_hash_password
./build/tests/test_s3_key
./build/tests/test_logger
./build/tests/test_metrics
./build/tests/test_lmtp_queue
./build/tests/test_lmtp_worker_db
./build/tests/test_memory_sampler

echo "All tests passed"
