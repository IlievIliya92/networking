/******************************** INCLUDE FILES *******************************/
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdint.h>

#include <inttypes.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>


#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/net_tstamp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <net/if.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

/********************************** DEFINES ***********************************/
#define SOCKET_TIMEOUT_SEC  1
#define RECV_BUFF_SIZE      1024

#define ETHERTYPE_SP        0x8809


/********************************* TYPEDEFS ***********************************/
typedef enum
{
    EXE_NAME = 0,
    INTERFACE,
    ARGUMENTS_N
} ptpArguments_t;


/* OSSP protocol definitions */
typedef enum
{
    EVENT = 0,
    INFO
} spEvents_t;

struct sp_header {
    uint8_t  sp_sType;               /* OSSP protocol - 0x0A */
    uint8_t  sp_oui[3];              /* Organizationally Uniqe Identifier
                                       encodes the identifier assigned to the
                                       standard body ITU - International Telecommunication Union
                                       value - 00-19-A7 */
    uint16_t sp_ouistype;            /* Subtype of ITU-OUI protocol
                                        value - 00-01 */
    uint8_t  sp_ouiver:4,            /* encodes the version of ITU-OUI protocol
                                        value - 1 */
             sp_event:1,             /* This bit indicates if it is an information message (0)
                                        or an event message (1)
                                      - event msg. is transmitted when there is a change in the transport synchronization.
                                      - info msg is transmitted every second in the absence of synchronization transport change. */
             sp_tsflag:1,            /* timestamp valid flag */
             sp_unused:2;            /* Reserved */
    uint8_t  sp_reserved[3];         /* Reserved - 3 octets*/

    uint8_t  sp_quality;             /* type */
    uint16_t sp_len;                 /* length */

    uint8_t  sp_ssm;                 /* Reserved:4 SSM code:4 */

    uint8_t  sp_padding[32];         /* purpoused for future enhacement TLVs and padding (32 - 1486 octets)*/
} __attribute__((__packed__));

struct pkt_sp {
    struct ether_header eh;
    struct sp_header sph;
} __attribute__((__packed__));

/********************************* GLOBAL DATA *********************************/
extern int errno;

/********************************* LOCAL DATA *********************************/


/******************************* INTERFACE DATA *******************************/

/******************************* LOCAL FUNCTIONS ******************************/
static
void hexdump(char *p, int len)
{
    char buf[128];
    int i, j, k = 0, i0;

    /* hexdump routine */
    for (i = 0; i < len; ) {
        memset(buf, sizeof(buf), ' ');
        sprintf(buf, "%04d: ", k);
        i0 = i;
        for (j=0; j < 16 && i < len; i++, j++)
            sprintf(buf+6+j*3, "%02x ", (uint8_t)(p[i]));
        i = i0;
        for (j=0; j < 16 && i < len; i++, j++)
            sprintf(buf+6+j + 48, "%c",
                isprint(p[i]) ? p[i] : '.');
        printf("%s\n", buf);
        k = k+10;
    }
}

static
int spPacket(uint8_t *recvbuf, int recbufLen)
{
    struct pkt_sp *pkt = NULL;
    struct ether_header *eh = NULL;
    struct sp_header *sph = NULL;
    int recv_len = -1;

    pkt = (struct pkt_sp *)recvbuf;
    eh = &pkt->eh;
    sph = &pkt->sph;

    hexdump(recvbuf, recbufLen);

    /* Just a confirmation that we have received SP packet */
    fprintf(stdout, "SP packet received: ITU-OUI event: %s\n", sph->sp_event ? "Event msg": "Information msg");

    return recv_len;
}

/***************************** MAIN **********************************/
int main(int argc, char *argv[])
{
    if (ARGUMENTS_N != argc) {
       fprintf(stdout, "usage: ./listener [interface]\n");
       fprintf(stdout, "(e.g. `listener eth1')\n");

       return -1;
    }

    const uint8_t *interface = argv[INTERFACE];

    uint8_t receiveBuffer[RECV_BUFF_SIZE];
    int recvLen = 0;

    int64_t ts_out = 0;

    int sock = -1;

    struct ifreq if_idx;
    struct sockaddr_ll socket_address;
    int socket_addressSize = 0;

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_SP));
    if (sock < 0)
    {
        fprintf(stderr, "Failed to create the socket! %s\n", strerror(errno));
        return 1;
    }
    else
    {
        fprintf(stdout, "Socket created ...\n");
    }

    const int len = strnlen(interface, IFNAMSIZ);
    if (len == IFNAMSIZ) {
        fprintf(stderr, "Incompatible iface name");
        return 1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, len) < 0)
    {
        fprintf(stderr, "Setup SP: setsockopt1 failed: %s\n", strerror(errno));
        goto exit;
    }

    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) < 0)
    {
        fprintf(stderr,  "Setup SP: setsockopt2 failed: %s\n", strerror(errno));
        goto exit;
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

    struct timeval tv;
    tv.tv_sec = SOCKET_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        fprintf(stderr, "Setup SP: setsockopt3 failed: %s\n", strerror(errno));
        goto exit;
    }

    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0)\
    {
        fprintf(stderr, "ioctl SIOCGIFINDEX %s\n",  strerror(errno));
        goto exit;
    }

    /* Clear sockaddr_ll struct */
    memset(&socket_address, 0, sizeof(socket_address));

    /* Fill out sockaddr_ll. */
    socket_address.sll_family   = PF_PACKET;
    socket_address.sll_protocol = ETHERTYPE_SP;
//    socket_address.sll_hatype   = ARPHRD_VOID;

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    socket_addressSize = sizeof(socket_address);

    while(1)
    {
        memset(receiveBuffer, 0, sizeof(receiveBuffer));

        recvLen = recvfrom(sock, (char *)receiveBuffer, sizeof(receiveBuffer), 0,
                          (struct sockaddr *)&socket_address, &socket_addressSize);
        if (recvLen < 0)
        {
            fprintf(stderr, "packet receive error: %s\n",  strerror(errno));
        }
        else
        {
            spPacket(receiveBuffer, recvLen);
        }
   }

exit:
    fprintf(stderr, "Clossing the application ...\n");
    close(sock);

    return -1;
}