#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>

int main ()
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;
    char address[200] = {0};

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            strcat(address, ifa->ifa_name);
            strcat(address, addr);
            strcat(address, "\n");
        }
    }

    printf("%s\n", address);

    freeifaddrs(ifap);
    return 0;
}