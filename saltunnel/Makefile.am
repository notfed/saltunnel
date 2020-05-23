C_FILES=src/cache.c src/crypto_secretbox_salsa20poly1305.c src/cryptostream_decrypt.c src/cryptostream_decrypt_feed.c src/cryptostream_decrypt_parallel.c src/cryptostream_encrypt.c src/cryptostream_encrypt_feed.c src/cryptostream_encrypt_parallel.c src/cryptostream_vector.c src/hypercounter.c src/log.c src/nonce.c src/oops.c src/rwn.c src/saltunnel.c src/saltunnel_kx.c src/saltunnel_mx_parallel.c src/saltunnel_mx_serial.c src/saltunnel_tcp_client_forwarder.c src/saltunnel_tcp_server_forwarder.c src/stopwatch.c src/tcpclient.c src/tcpserver.c src/threadpool.c src/threadpool_barrier.c src/uint16.c src/uint32.c src/uint64.c
TEST_FILES=saltunnel-test.c test/cache.test.c test/chaos.c test/cryptostream_vector.test.c test/log.test.c test/nonce.test.c test/rwn.test.c test/saltunnel.test.c test/saltunnel_tcp_forwarder.test.c test/tcp.test.c

saltunnel_client_SOURCES = ${C_FILES} saltunnel-client.c
saltunnel_server_SOURCES = ${C_FILES} saltunnel-server.c
bin_PROGRAMS = saltunnel-client saltunnel-server 

saltunnel_test_SOURCES = ${C_FILES} ${TEST_FILES}
saltunnel_test_CFLAGS = -I src/
testdir = .
test_PROGRAMS = saltunnel-test
TESTS = saltunnel-test

AM_LDFLAGS = -lpthread
LDADD = /usr/local/lib/libsodium.a
