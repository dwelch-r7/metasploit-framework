#include "redismodule.h"
#include <fcntl.h>
#include <unistd.h>

/* Independent compiler/loader control; it does not execute a payload buffer. */
static int NativeWrite(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 3) return RedisModule_WrongArity(ctx);
    size_t length;
    const char *path = RedisModule_StringPtrLen(argv[1], NULL);
    const char *value = RedisModule_StringPtrLen(argv[2], &length);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return RedisModule_ReplyWithError(ctx, "ERR Native control could not open its file");
    ssize_t written = write(fd, value, length);
    int closed = close(fd);
    if (written < 0 || (size_t)written != length || closed != 0)
        return RedisModule_ReplyWithError(ctx, "ERR Native control could not write its file");
    return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);
    if (RedisModule_Init(ctx, "mcvnativec", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
    return RedisModule_CreateCommand(ctx, "mcv.write", NativeWrite, "write", 1, 1, 1);
}
