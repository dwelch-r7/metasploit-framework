/* Independent native service/session/read control using upstream public APIs. */
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if(argc != 2) return EXIT_FAILURE;
    UA_Client *client = UA_Client_new();
    if(!client) return EXIT_FAILURE;
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));
    UA_Client_getConfig(client)->timeout = 3000;
    size_t count = 0;
    UA_EndpointDescription *endpoints = NULL;
    UA_StatusCode status = UA_Client_getEndpoints(client, argv[1], &count, &endpoints);
    printf("OPCUA_NATIVE_ENDPOINT_STATUS=%s\n", UA_StatusCode_name(status));
    printf("OPCUA_NATIVE_ENDPOINTS=%zu\n", count);
    UA_Array_delete(endpoints, count, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(status == UA_STATUSCODE_GOOD && count == 0) status = UA_STATUSCODE_BADNOTFOUND;
    if(status != UA_STATUSCODE_GOOD) goto done;
    status = UA_Client_connect(client, argv[1]);
    printf("OPCUA_NATIVE_SESSION_STATUS=%s\n", UA_StatusCode_name(status));
    if(status != UA_STATUSCODE_GOOD) goto done;
    UA_Variant value;
    UA_Variant_init(&value);
    status = UA_Client_readValueAttribute(client,
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO_SOFTWAREVERSION), &value);
    if(status == UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_STRING])) {
        UA_String *version = (UA_String *)value.data;
        printf("OPCUA_NATIVE_VERSION=%.*s\n", (int)version->length, version->data);
    } else {
        status = UA_STATUSCODE_BADTYPEMISMATCH;
    }
    UA_Variant_clear(&value);
done:
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return status == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
