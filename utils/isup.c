#include <stdio.h>        // printf
#include <unistd.h>       // printf
#include <string.h>       // strncpy
#include <sys/socket.h>   // AF_INET
#include <sys/ioctl.h>    // SIOCGIFFLAGS
#include <errno.h>        // errno
#include <netinet/in.h>   // IPPROTO_IP
#include <net/if.h>       // IFF_*, ifreq

#define ERROR(fmt, ...) do { printf(fmt, __VA_ARGS__); return -1; } while(0)

int CheckLink(char *ifname) {
    int state = -1;
    int socId = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (socId < 0)
        return -1;

    struct ifreq if_req;
    (void) strncpy(if_req.ifr_name, ifname, sizeof(if_req.ifr_name));
    int rv = ioctl(socId, SIOCGIFFLAGS, &if_req);
    close(socId);

    if ( rv == -1)
        return -1;

    return (if_req.ifr_flags & IFF_UP) && (if_req.ifr_flags & IFF_RUNNING);
}

int main() {
    printf("%d\n", CheckLink("eno1"));
}