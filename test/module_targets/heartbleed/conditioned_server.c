/* Deterministic lab heap layout, never a replacement heartbeat implementation.
 * The public CRYPTO allocator hook puts a disposable RSA factor beyond a TLS
 * buffer's requested allocation. Only the genuine vulnerable SDK overreads it.
 * Ordinary upstream s_server controls are retained separately in the lab.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

static unsigned char factor[256];
static size_t factor_size;
static volatile sig_atomic_t stopping;

static size_t allocation_size(size_t requested) {
    return requested >= 16384 && requested <= 20000 ? requested + 65536 : requested;
}

static void seed_slack(void *memory, size_t requested) {
    if (memory && factor_size && allocation_size(requested) != requested) {
        unsigned char *slack = (unsigned char *)memory + requested;
        memset(slack, 0x5a, 65536);
        memcpy(slack + 64, "HEARTBLEED_LAB_FACTOR", sizeof("HEARTBLEED_LAB_FACTOR") - 1);
        memcpy(slack + 96, factor, factor_size);
    }
}

static void *lab_malloc(size_t requested) {
    void *memory = malloc(allocation_size(requested));
    seed_slack(memory, requested);
    return memory;
}

static void *lab_realloc(void *previous, size_t requested) {
    void *memory = realloc(previous, allocation_size(requested));
    seed_slack(memory, requested);
    return memory;
}

static void stop(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static void die(const char *operation) {
    fprintf(stderr, "Operation failed: %s\n", operation);
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main(int argc, char **argv) {
    FILE *key_file;
    RSA *rsa;
    SSL_CTX *context;
    int listener, enabled = 1, port;
    struct sockaddr_in address;
    struct timeval timeout = {2, 0};
    unsigned char big_endian[256];
    size_t index;
    struct sigaction action;

    if (argc != 4) die("usage: conditioned_server PORT CERT KEY");
    port = atoi(argv[1]);
    if (port < 1024 || port > 65535) die("invalid port");
    if (!CRYPTO_set_mem_functions(lab_malloc, lab_realloc, free)) die("allocator hook");
    SSL_library_init();
    SSL_load_error_strings();
    key_file = fopen(argv[3], "r");
    if (!key_file) die("open disposable key");
    rsa = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!rsa) die("read disposable RSA key");
    factor_size = BN_num_bytes(rsa->p);
    if (factor_size > sizeof(factor)) die("factor exceeds bound");
    BN_bn2bin(rsa->p, big_endian);
    for (index = 0; index < factor_size; index++) factor[index] = big_endian[factor_size - 1 - index];
    RSA_free(rsa);

    context = SSL_CTX_new(SSLv23_server_method());
    if (!context) die("SSL context");
    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION);
    if (SSL_CTX_use_certificate_file(context, argv[2], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, argv[3], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1) die("disposable certificate/key");
    if (SSL_CTX_set_cipher_list(context, "AES128-SHA") != 1) die("cipher list");

    memset(&action, 0, sizeof(action));
    action.sa_handler = stop;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) die("socket");
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((unsigned short)port);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 16)) die("listen");
    printf("SDK=%s conditioned_heap=true factor_bytes=%zu port=%d\n", SSLeay_version(SSLEAY_VERSION), factor_size, port);
    fflush(stdout);
    while (!stopping) {
        SSL *connection;
        int peer = accept(listener, NULL, NULL);
        if (peer < 0) {
            if (errno == EINTR) continue;
            die("accept");
        }
        setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        connection = SSL_new(context);
        if (!connection || SSL_set_fd(connection, peer) != 1) die("SSL connection");
        {
            struct timespec started, current;
            int accepted, error;
            clock_gettime(CLOCK_MONOTONIC, &started);
            while (!stopping && (accepted = SSL_accept(connection)) != 1) {
                error = SSL_get_error(connection, accepted);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) break;
                /* Heartbeat handling asks the application to read again even
                 * on a blocking socket. Flush the handshake BIO before retrying
                 * so a final short TLS fragment is not held until shutdown.
                 */
                if (BIO_flush(SSL_get_wbio(connection)) != 1) break;
                clock_gettime(CLOCK_MONOTONIC, &current);
                if (current.tv_sec - started.tv_sec >= 6) break;
            }
        }
        SSL_free(connection);
        close(peer);
        ERR_clear_error();
    }
    close(listener);
    SSL_CTX_free(context);
    return 0;
}
