/******************************** INCLUDE FILES *******************************/
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>


/*   GUIDANCE:
 *
 *   1. Create a socket.

        - The protocol family should be the Internet protocol family, represented by the constant
    PF_INET.
        - For the purposes of UDP and multicast, best-effort semantics are used (SOCK_DGRAM).
        - The Internet protocol is most commonly set to TCP (IPPROT0_TCP) or UDP (IPPROT0_UDP).
    For multicast, this should always be set to IPPROT0_UDP.

 *   2. Optionally set the scope for the packets.
 *   3. Send the data on the socket.
 *   4. Close the socket.
 */

/********************************** DEFINES ***********************************/
#define SEND_DELAY_SEC  0.1
#define MIN_PORT        1024    /* minimum port allowed */
#define MAX_PORT        65535   /* maximum port allowed */
#define LOOPBACK_ENB    0

typedef enum
{
    EXE_NAME = 0,
    MULTICAST_GROUP,
    PORT,
    MULTICAST_INTERFACE,
    TTL,
    MESSAGE,
    ARGUMENTS_N
} ptpArguments_t;

/********************************* LOCAL DATA *********************************/

/******************************* INTERFACE DATA *******************************/

/******************************* LOCAL FUNCTIONS ******************************/


/***************************** INTERFACE FUNCTIONS ****************************/
int main(int argc, char *argv[])
{
    if (ARGUMENTS_N != argc) {
       fprintf(stdout, "usage: ./sender [multicast IP] [port number] [interface ip] [ttl] [message]\n");
       fprintf(stdout, "(e.g. for IGMPv3, `sender 224.0.0.22 1900 192.168.10.10 1 test`)\n");

       return 1;
    }

    struct sockaddr_in addr;
    char* group = argv[MULTICAST_GROUP];
    int port = atoi(argv[PORT]);

    char* interface = argv[MULTICAST_INTERFACE];
    struct in_addr interface_addr;
    int addr_size = 0;

    unsigned char ttl = atoi(argv[TTL]);
    int ttl_size = 0;

    unsigned char loopback = LOOPBACK_ENB;
    int loopback_size;
    loopback_size = sizeof(loopback);

    int sock = -1;
    int nbytes = -1;

    const char *message = argv[MESSAGE];
    const int delay_secs = SEND_DELAY_SEC;

    /* validate the port range */
    if ((port < MIN_PORT) || (port > MAX_PORT)) {
        fprintf(stderr, "Invalid port number argument %d.\n", port);
        fprintf(stderr, "Valid range is between %d and %d.\n", MIN_PORT, MAX_PORT);

        return -1;
    }

    /*
     *   1.1. Create  UDP socket
     *
     *   protocolFamily   PF_INET     Internet protocol family
     *   type             SOCK_DGRAM  Datagram socket
     *   protocol         IPPROTO_UDP User datagram protocol
     *
     */
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        fprintf(stderr, "Failed to create the UDP socket!\n");
        return 1;
    }
    else
    {
        fprintf(stdout, "UDP socket created ...\n");
    }

    /*
     * 1.2. Set up destination address
     *
     *   Now that the socket descriptor has been created,
     *   the destination address structure needs to be
     *   prepared before packets can be sent.
     *   For this, a sockaddr data structure needs to be populated
     *   with the destination address information.
     */
    memset(&addr, 0x0, sizeof(addr));

    addr.sin_family = AF_INET; /* protocol family (AF_INET) */
    addr.sin_addr.s_addr = inet_addr(group); /* 32 bit Internet address represents
                                              *  the binary value of the IP address.
                                              */
    addr.sin_port = htons(port); /* 16 bit address port */
    /* addr.sin_zero - unused */

    /*
     * 1.3. Set up the TTL
     * The TTL field for outgoing multicast traffic is used to
     * control the scope of the multicast packets.
     * A TTL value of 1 will restrict a multicast  packet to the local subnet.
     *
     * Every multicast-specific socket option is applied at the IP level (IPPROT0_IP)
     */

    /* time to live (hop count) */
    ttl_size = sizeof(ttl);
    ttl = 1; /* set the new ttl to 1 */
    if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*) &ttl, ttl_size)) < 0)
    {
        fprintf(stderr, "Failed to set up TTL!\n");
        goto exit;
    }
    else
    {
        fprintf(stdout, "TTL succesfully updated ...\n");
    }


    addr_size = sizeof(interface_addr);
    interface_addr.s_addr = inet_addr(interface);
    /* set the interface */
    if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &interface_addr, addr_size)) < 0)
    {
        fprintf(stderr, "Failed to set multicast interface!\n");
        goto exit;
    }
    else
    {
        fprintf(stdout, "Multicast interface set (ip: %s)\n", interface);
    }

    /* set the new loopback value */
    if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, loopback_size)) < 0)
    {
        fprintf(stderr, "Failed to set loopback option!\n");
        goto exit;
    }
    else
    {
        fprintf(stdout, "Loopback: %s\n", loopback ? "ON": "OFF");
    }

    fprintf(stdout, "Streaming multicast messages ...\nPacket data: %s\n", message);

    while (1) {
        nbytes = sendto(sock, message, strlen(message), 0,
                        (struct sockaddr*) &addr, sizeof(addr));
        if (nbytes < 0) {
            fprintf(stderr, "sendto failed!\n");
            goto exit;
        }

        sleep(delay_secs); /* Unix sleep is seconds */
    }

exit:
    close(sock);

    return -1;
}