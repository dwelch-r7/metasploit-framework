#include <stdio.h>
#include <libssh/libssh.h>
int main(void) {
    puts(ssh_version(0));
    return 0;
}
