#include <stdio.h>
#include <unistd.h>
int main(void) {
  printf("MODULE_TARGET_NATIVE_ELF uid=%ld gid=%ld\n", (long)getuid(), (long)getgid());
  return 0;
}
