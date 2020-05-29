/******************************** INCLUDE FILES *******************************/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/********************************** DEFINES ***********************************/
#define MSGBUFSIZE      256

#define MIN_PORT        1024    /* minimum port allowed */
#define MAX_PORT        65535   /* maximum port allowed */

#define REUSESOCKET     1

typedef enum
{
    EXE_NAME = 0,
    MULTICAST_GROUP,
    PORT,
    ARGUMENTS_N
} ptpArguments_t;



/*   GUIDANCE:
 *
 *   1. Create a socket.
 *   2. Optionally set the port reuse socket option.
 *   3. Bind to the socket.
 *   4. Join the multicast group.
 *   5. Receive multicast data.
 *   6. Drop the multicast group.
 *   7. Close the socket.
 *
 */

/********************************* LOCAL DATA *********************************/


/******************************* INTERFACE DATA *******************************/

/******************************* LOCAL FUNCTIONS ******************************/


/***************************** INTERFACE FUNCTIONS ****************************/
int main(int argc, char *argv[])
{

    if (ARGUMENTS_N != argc) {
       fprintf(stdout, "usage: ./listener [multicast IP] [port number] [message]\n");
       fprintf(stdout, "(e.g. for IGMPv3, `listener 224.0.0.22 1900 test`)\n");

       return -1;
    }

    char msgbuf[MSGBUFSIZE];

    int sock = -1;
    int addrlen = 0;
    int nbytes = -1;

    unsigned int reuseSocket = REUSESOCKET;

    struct sockaddr_in addr;
    struct ip_mreq mreq;

    char* group = argv[MULTICAST_GROUP];
    int port = atoi(argv[PORT]);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        fprintf(stderr, "Failed to create the UDP socket!\n");
        return 1;
    }
    else
    {
        fprintf(stdout, "UDP socket created ...\n");
    }

    /* allow multiple sockets to use the same PORT number */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &reuseSocket, sizeof(reuseSocket)) < 0)
    {
        fprintf(stderr, "Reusing ADDR failed!\n");
        goto exit;
    }
    else
    {
        fprintf(stdout, "ADDR set as reusable ...\n");
    }


    /* set up destination address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // differs from sender
    addr.sin_port = htons(port);

    /* bind to receive address */
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    {
        fprintf(stderr, "Socket bind failed!\n");
        goto exit;
    }
    else
    {
        fprintf(stdout, "Socket bind ...\n");
    }

    /* construct an IGMP join request structure */
    /* use setsockopt() to request that the kernel join a multicast group */
    mreq.imr_multiaddr.s_addr = inet_addr(group);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq)) < 0)
    {
        fprintf(stderr, "Joining group failed!\n");
        goto exit;
    }
    else
    {
        fprintf(stdout, "Joining group %s\n", group);
    }



    /* now just enter a read loop */
    while (1) {
        /* clear the receive buffers & structs */
        memset(msgbuf, 0, sizeof(msgbuf));
        addrlen = sizeof(addr);
        memset(&addr, 0, addrlen);

        nbytes = recvfrom(sock, msgbuf, MSGBUFSIZE, 0,
                          (struct sockaddr *) &addr, &addrlen);
        if (nbytes < 0) {
            fprintf(stderr, "recvfrom failed!\n");
            goto exit1;
        }

        fprintf(stdout, "Received %d bytes from %s: ", nbytes, inet_ntoa(addr.sin_addr));
        fprintf(stdout, "%s\n", msgbuf);
     }

exit1:
    if ((setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
         (void*) &mreq, sizeof(mreq))) < 0)
    {
        fprintf(stderr, "Failed to leave multicast group\n");
    }
    else
    {
        fprintf(stdout, "Multicast group left!\n");
    }

 exit:
    close(sock);

    return -1;
}