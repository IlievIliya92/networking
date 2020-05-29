#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DST_PORT    58007
#define SRC_PORT    57002

#define IP      "127.0.0.1"

int main(int argc, char *argv[]) {
    struct sockaddr_in addr, srcaddr;
    int fd;
    char message[] = "HI!";

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(IP);
    addr.sin_port = htons(DST_PORT);

    memset(&srcaddr, 0, sizeof(srcaddr));
    srcaddr.sin_family = AF_INET;
    srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srcaddr.sin_port = htons(SRC_PORT);

    if (bind(fd, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
        perror("bind");
        exit(1);
    }

    while (1) {
        if (sendto(fd, message, sizeof(message), 0, (struct sockaddr *) &addr,
                sizeof(addr)) < 0) {
            perror("sendto");
            exit(1);
        }
        sleep(1);
    }
    return 0;
}

