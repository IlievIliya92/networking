/******************************** INCLUDE FILES *******************************/

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>


#include <errno.h>

#include <linux/net_tstamp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

/*
 * https://books.google.bg/books?id=kgUsDgAAQBAJ&pg=PA246&lpg=PA246&dq=ITU-OUI&source=bl&ots=5Ooqxz_mxb&sig=ACfU3U252eQgrTLX-S_aL8IYIF-xrySXVA&hl=en&sa=X&ved=2ahUKEwiky5e_m7DpAhVRrxoKHaO4C8kQ6AEwAHoECAoQAQ#v=onepage&q&f=false
 */

/********************************** DEFINES ***********************************/
#define SEND_DELAY_SEC  1
#define SEND_BUFF_SIZE  1024


#define ETHERTYPE_SP    0x8809
#define SPTYPE_OSSP     0x0A

/* Organizationally Uniqe Identifier*/
#define OUI_ITU0        0x00
#define OUI_ITU1        0x19
#define OUI_ITU2        0xA7

#define OUI_SUBTYPE    0x0001

#define OUI_VER         0x1

/********************************* TYPEDEFS ***********************************/
typedef enum
{
    EXE_NAME = 0,
    DEST_MAC,
    HOST_IFACE,
    ARGUMENTS_N
} spArguments_t;

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
int init_sp_packet(unsigned char *sendbuf, int sock, const char *interface, const char *destMac) {
    struct ifreq if_mac;
    struct pkt_sp *pkt = NULL;
    struct ether_header *eh = NULL;
    struct sp_header *sp = NULL;
    uint8_t shost[6];
    uint8_t dhost[6];

    memset(sendbuf, 0x00, SEND_BUFF_SIZE);
    pkt = (struct pkt_sp *) sendbuf;

    /* Get the MAC address of the interface to send on */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0) {
        fprintf(stderr, "\n[%s] FSIOCGIFHWADDR\n", __func__);
        return -1;
    }

    sscanf(destMac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dhost[0], &dhost[1], &dhost[2], &dhost[3], &dhost[4], &dhost[5]);

    eh = &pkt->eh;
    eh->ether_type = htons(ETHERTYPE_SP);   /*SP ethertype*/
    memcpy(eh->ether_shost, (unsigned char*)if_mac.ifr_hwaddr.sa_data, ETH_ALEN);  /*source mac*/
    memcpy(eh->ether_dhost, dhost, ETH_ALEN);  /*destination mac*/

    /* Fill in slow protocol header */
    sp = &pkt->sph;
    sp->sp_sType = SPTYPE_OSSP;

    sp->sp_oui[0] = OUI_ITU0;
    sp->sp_oui[1] = OUI_ITU1;
    sp->sp_oui[2] = OUI_ITU2;

    sp->sp_ouistype = htons(OUI_SUBTYPE);

    sp->sp_ouiver = htons(OUI_VER);
    sp->sp_event  = INFO;
    sp->sp_tsflag = 0;
    sp->sp_unused = 0;

    memset(sp->sp_reserved, 0x00, sizeof(sp->sp_reserved));

    sp->sp_quality = 0x01;
    sp->sp_len = htons(0x0004);
    sp->sp_ssm = 0x02;

    return 0;
}

/***************************** INTERFACE FUNCTIONS ****************************/
int main(int argc, char *argv[])
{
    if (ARGUMENTS_N != argc) {
       fprintf(stdout, "usage: ./sender [dest mac] [host interface]\n");
       fprintf(stdout, "(e.g. `sender 00:1F:59:AA:E7:91 eth1`)\n");

       return 1;
    }

    uint8_t sendBuffer[SEND_BUFF_SIZE];

    const uint8_t* destMacStr = argv[DEST_MAC];
    const uint8_t* interface = argv[HOST_IFACE];

    int sock = -1;
    int nbytes = -1;
    int tx_len = 0;

    const int delay_secs = SEND_DELAY_SEC;

    struct ifreq if_idx;
    struct sockaddr_ll socket_address;
    uint8_t srcMac[6];

    /*
     *   1.1. Create RAW socket
     *
     *   protocolFamily   AF_PACKET      Internet protocol family
     *   type             SOCK_RAW       RAW socket
     *   protocol         ETH_P_ALL      All layer two
     *
         */
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_SP));
    if (sock < 0)
    {
        fprintf(stderr, "Failed to create the RAW socket! %s\n",  strerror(errno));
        return -1;
    }
    else
    {
        fprintf(stdout, "RAW socket created ...\n");
    }


    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0) {
        fprintf(stderr, "ioctl SIOCGIFINDEX\n");
        goto exit;
    }

    /* Fill out sockaddr_ll. */
    socket_address.sll_family   = PF_PACKET;
    socket_address.sll_protocol = ETHERTYPE_SP;
    socket_address.sll_hatype   = ARPHRD_VOID;

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    if (bind(sock, (const struct sockaddr *)&socket_address, sizeof(socket_address)) < 0)
    {
        fprintf(stderr, "Failed to bind socket! %s\n",  strerror(errno));
        goto exit;
    }

    if (init_sp_packet(sendBuffer, sock, interface, destMacStr) < 0)
    {
        fprintf(stderr, "Packet init failed!!\n");
        goto exit;
    }

    fprintf(stdout, "Streaming slow protocol messages ...\n");

    tx_len = sizeof(struct pkt_sp);
    while (1) {
        nbytes = send(sock, sendBuffer, tx_len, 0);
        if (nbytes < 0) {
            fprintf(stderr, "sendto failed! %s\n",  strerror(errno));
            goto exit;
        }

        sleep(delay_secs); /* Unix sleep is seconds */
    }

exit:
    fprintf(stderr, "Clossing the application ...\n");
    close(sock);

    return -1;
}