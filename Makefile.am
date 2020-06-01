C_FILES=src/cache.c src/saltunnel_crypto.c src/cryptostream_decrypt.c src/cryptostream_decrypt_feed.c src/cryptostream_decrypt_parallel.c src/cryptostream_encrypt.c src/cryptostream_encrypt_feed.c src/cryptostream_encrypt_parallel.c src/cryptostream_vector.c src/hypercounter.c src/log.c src/nonce.c src/oops.c src/rwn.c src/saltunnel_init.c src/saltunnel_kx.c src/saltunnel_mx.c src/saltunnel_mx_parallel.c src/saltunnel_mx_serial.c src/saltunnel_tcp_client_forwarder.c src/iopoll.c src/saltunnel_tcp_server_forwarder.c src/stopwatch.c src/tcpclient.c src/tcpserver.c src/threadpool.c src/threadpool_barrier.c src/uint16.c src/uint32.c src/uint64.c src/config.c src/waitlist.c src/concurrentlist.c src/saltunnel_tcp_forwarder_thread.c src/consttime.c src/csprng.c src/hex2bin.c src/thread_tracker.c src/keyfile.c
TEST_FILES=saltunnel-test.c tests/cache.test.c tests/stunted_rwv.c tests/cryptostream_vector.test.c tests/log.test.c tests/nonce.test.c tests/rwn.test.c tests/saltunnel.test.c tests/saltunnel_tcp_forwarder.test.c tests/tcp.test.c tests/hypercounter.test.c tests/waitlist.test.c tests/concurrentlist.test.c tests/consttime.test.c tests/csprng.test.c tests/hex2bin.test.c

saltunnel_SOURCES = ${C_FILES} saltunnel.c
bin_PROGRAMS = saltunnel

saltunnel_test_SOURCES = ${C_FILES} ${TEST_FILES}
saltunnel_test_CFLAGS = -I src/ -g3 -O0
testdir = .
test_PROGRAMS = saltunnel-test
TESTS = saltunnel-test

man1_MANS = docs/saltunnel.1

AM_CFLAGS = -g3 -O0
LDADD = -l:libsodium.a -lpthread
