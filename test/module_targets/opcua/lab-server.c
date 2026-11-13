/* Uses the upstream public configuration API; the protocol stack is unchanged. */
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

static volatile UA_Boolean running = true;
static void stop_server(int sig) { (void)sig; running = false; }

int main(int argc, char **argv) {
    if(argc != 3) return EXIT_FAILURE;
    unsigned long port = strtoul(argv[1], NULL, 10);
    unsigned long buffer = strtoul(argv[2], NULL, 10);
    if(port == 0 || port > 65535 || buffer < 4096 || buffer > 65536)
        return EXIT_FAILURE;
    UA_ServerConfig config;
    memset(&config, 0, sizeof(config));
    UA_StatusCode status = UA_ServerConfig_setMinimalCustomBuffer(
        &config, (UA_UInt16)port, NULL, (UA_UInt32)buffer, (UA_UInt32)buffer);
    if(status != UA_STATUSCODE_GOOD) return EXIT_FAILURE;
    UA_Server *server = UA_Server_newWithConfig(&config);
    if(!server) return EXIT_FAILURE;
    signal(SIGTERM, stop_server);
    signal(SIGINT, stop_server);
    status = UA_Server_run(server, &running);
    UA_Server_delete(server);
    return status == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
