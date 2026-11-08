## Vulnerable Application

Redis is an in-memory data structure project implementing a distributed,
in-memory key-value database with optional durability. Redis supports strings,
lists, maps, sets, sorted sets, HyperLogLogs, bitmaps, streams, and spatial indexes.

This module leverages Redis functionality to upload a file to a directory writable
by the Redis user. The exact contents cannot be completely controlled because the
file uses Redis's database format.

Tested container versions include:

 - Redis 5.0.6
 - Redis 4.0.14
 - Redis 6.2.14, with and without password authentication
 - Redis 7.2.4, with protected configuration disabled and enabled

The module needs permission to read and change Redis snapshot configuration and
save the database. Redis 7 defaults to `enable-protected-configs no`, which blocks
changes to `dir` and `dbfilename` even when `CONFIG GET` succeeds. The check reports
this configuration as Safe. With `enable-protected-configs local`, configuration
changes require a connection originating from Redis's loopback interface or a
Unix socket; a host loopback port forwarded into Docker is not such a connection.

The check only reads configuration and reports Appears when file upload may be
possible. It does not write a test file or verify filesystem permissions, Redis
ACL permissions for every required command, or the final destination. Use `run`
to perform the requested upload.

## Verification Steps

  1. Do: `use auxiliary/scanner/redis/file_upload`
  2. Do: `set rhosts [ips]`
  3. Do: `set LocalFile [local_file_path_to_be_uploaded]`
  4. Do: `set RemoteFile [remote_file_destination]`
  5. Do: `check` to assess the snapshot configuration without changing it.
  6. Do: `run`

## Options

### DISABLE_RDBCOMPRESSION

If set to `true`, the module disables Redis compression before saving and restores
the original setting after a successful upload. Defaults to `true`.

### FLUSHALL

If set to `true`, redis server will remove all redis data before saving. Defaults to `false`.

### LocalFile

Path to the local file to be uploaded.

### RemoteFile

Path, or file name, to store the file as on the Redis server.

## Scenarios

### Redis: 4.0.14 inside a docker container

```
msf auxiliary(scanner/redis/file_upload) > set RHOSTS 172.17.0.2
RHOSTS => 172.17.0.2
msf auxiliary(scanner/redis/file_upload) > set LocalFile redis_upload_test.txt
LocalFile => redis_upload_test.txt
msf auxiliary(scanner/redis/file_upload) > set RemoteFile redis_upload_test.txt
RemoteFile => redis_upload_test.txt
msf auxiliary(scanner/redis/file_upload) > run

[+] 172.17.0.2:6379       - 172.17.0.2:6379       -- saved 23 bytes inside of redis DB at redis_upload_test.txt
[*] 172.17.0.2:6379       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Automated container tests

See the [redis target lab](../../../../../test/module_targets/redis/README.md) for reproducible container setup and
functional tests. From the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb redis
```
