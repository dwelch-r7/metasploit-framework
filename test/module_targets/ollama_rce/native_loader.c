#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* Record the real loader process, then allow its normal program to continue. */
__attribute__((constructor)) static void native_loader_proof(void) {
  char executable[4096];
  ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
  if (length < 0) return;
  executable[length] = '\0';
  /* The fixture asserts absence before local control and owns the later arm. */
  unlink("/etc/ld.so.preload");
  int output = open("/tmp/module-target-ollama-native-proof", O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (output < 0) return;
  dprintf(output, "{\"pid\":%d,\"ppid\":%d,\"uid\":%d,\"exe\":\"%s\"}\n", getpid(), getppid(), getuid(), executable);
  close(output);
}
