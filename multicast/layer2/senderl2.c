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

/********************************** DEFINES ***********************************/
#define SEND_DELAY_SEC  1
#define SEND_BUFF_SIZE  1024
#define ETHERTYPE_PTP   0x88F7

/********************************* TYPEDEFS ***********************************/
typedef enum
{
    EXE_NAME = 0,
    DEST_MAC,
    HOST_IFACE,
    ARGUMENTS_N
} ptpArguments_t;

enum ptp_msg_type
{
    SYNC = 0x0,
    DELAY_REQ = 0x1,
    FOLLOW_UP = 0x8,
    DELAY_RESP = 0x9,
};

struct ptp_header {
    uint8_t  ptp_ts:4,              /*transportSpecific*/
             ptp_type:4;            /*messageType*/
    uint8_t  ptp_v;                 /*versionPTP (4 bits in size)*/
    uint16_t ptp_ml;                /*messageLength*/
    uint8_t  ptp_dn;                /*domainNumber*/
    uint8_t  ptp_res;               /*reserved*/
    uint16_t ptp_flags;             /*flags*/
    uint64_t ptp_cf;                /*correctionField*/
    uint32_t ptp_res2;              /*reserved*/
    uint8_t  ptp_src[10];           /*sourcePortIdentity,8 byte mac,2 byte portId*/
    uint16_t ptp_sid;               /*sequenceId*/
    uint8_t  ptp_ctlf;              /*controlField*/
    uint8_t  ptp_lmi;               /*logMessageInterval*/
} __attribute__((__packed__));

struct pkt_ptp {
    struct ether_header eh;
    struct ptp_header ph;
    uint64_t s:48;
    uint32_t ns;
} __attribute__((__packed__));

union uint48_t {
    char c[6];
    uint64_t v:48;
};


/********************************* GLOBAL DATA *********************************/
extern int errno;

/********************************* LOCAL DATA *********************************/

/******************************* INTERFACE DATA *******************************/

/******************************* LOCAL FUNCTIONS ******************************/
static
inline void get_time(int in[2]) {
    if(in != NULL) {
        struct timespec ts = {0};
        clock_gettime(CLOCK_REALTIME, &ts);
        in[0] = (int) ts.tv_sec;
        in[1] = (int) ts.tv_nsec;
    }
}

static
void dump_payload(char *p, int len)
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
int is_little_endian()
{
    union {
        uint32_t i;
        char c[4];
    } u = {0x01020304};

    return u.c[0] == 4;
}

static
char *hton(char *in, long size, char *out) {
    if(is_little_endian()) {
        int i;
        for(i = 0; i < size; i++) {
            out[size-1-i] = in[i];
        }
    }
    else {
        out = in;
    }
}

static
int init_ptp_packet(unsigned char *sendbuf, int sock, const char *interface, const char *destMac, int ptp_mtype) {
    int i, j = 0;
    struct ifreq if_mac;
    struct pkt_ptp *pkt = NULL;
    struct ptp_header *ph = NULL;
    struct ether_header *eh = NULL;
    uint8_t shost[6];
    uint8_t dhost[6];

    memset(sendbuf, 0x00, SEND_BUFF_SIZE);
    pkt = (struct pkt_ptp *) sendbuf;

    /* Get the MAC address of the interface to send on */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0) {
        fprintf(stderr, "\n[%s] FSIOCGIFHWADDR\n", __func__);
        return -1;
    }

    sscanf(destMac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dhost[0], &dhost[1], &dhost[2], &dhost[3], &dhost[4], &dhost[5]);

    eh = &pkt->eh;
    eh->ether_type = htons(ETHERTYPE_PTP);              /*PTP over 802.3 ethertype*/
    memcpy(eh->ether_shost, (unsigned char*)if_mac.ifr_hwaddr.sa_data, ETH_ALEN);  /*source mac*/
    memcpy(eh->ether_dhost, dhost, ETH_ALEN);  /*destination mac*/

    ph = &pkt->ph;
    ph->ptp_ts = 0;
    ph->ptp_type = ptp_mtype;
    ph->ptp_v = 2;    /*PTPv2 IEEE1588-2008*/
    ph->ptp_ml = htons(sizeof(struct pkt_ptp) - sizeof(struct ether_header));
    ph->ptp_dn = 24;
    ph->ptp_flags = 0;
    ph->ptp_cf = 0;

    for(i = 0; i < 10; i++) {
        if (i == 3)
            ph->ptp_src[i] = 0xff;
        else if(i == 4)
            ph->ptp_src[i] = 0xfe;
        else if(i == 8 || i == 9)
            ph->ptp_src[i] = 0x00;
        else {
            ph->ptp_src[i] = shost[j];
            j++;
        }
    }

    ph->ptp_sid = 0;   /*Sequence number on each protocol iteration*/
    ph->ptp_ctlf = 0;  /*deprecated in PTPv2*/
    ph->ptp_lmi = 0;   /*irrelevant*/

    pkt->s = 0;
    pkt->ns = 0;

    return 0;
}

static
void timestamp_ptp_packet(unsigned char *sendbuff) {
    struct pkt_ptp *p = NULL;
    int t[2];

    p = (struct pkt_ptp *)sendbuff;
    get_time(t);
    union uint48_t n, n2;
    n.v = t[0];
    hton(n.c, 6, n2.c);
    dump_payload(n2.c, 6);
    p->s = n2.v;
    p->ns = htonl(t[1]);

    return;
}

static
void increment_ptp_packet(unsigned char *sendbuff) {
    struct pkt_ptp *p = NULL;
    struct ptp_header *ph = NULL;
    static uint16_t seqcnt;

    p = (struct pkt_ptp *)sendbuff;
    ph = &p->ph;
    /* Increment the sequence numer */
    seqcnt += 1;
    ph->ptp_sid = htons(seqcnt);

    return;
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
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
    socket_address.sll_protocol = ETH_P_ALL;
    socket_address.sll_hatype   = ARPHRD_VOID;
    //socket_address.sll_pkttype = PACKET_MULTICAST;

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    if (bind(sock, (const struct sockaddr *)&socket_address, sizeof(socket_address)) < 0)
    {
        fprintf(stderr, "Failed to bind socket! %s\n",  strerror(errno));
        goto exit;
    }

    if (init_ptp_packet(sendBuffer, sock, interface, destMacStr, SYNC) < 0)
    {
        fprintf(stderr, "Packet init failed!!\n");
        goto exit;
    }

    fprintf(stdout, "Streaming ptp l2 messages ...\n");

    tx_len = sizeof(struct pkt_ptp);
    while (1) {
        timestamp_ptp_packet(sendBuffer);
        nbytes = send(sock, sendBuffer, tx_len, 0);
        if (nbytes < 0) {
            fprintf(stderr, "sendto failed! %s\n",  strerror(errno));
            goto exit;
        }
        increment_ptp_packet(sendBuffer);

        sleep(delay_secs); /* Unix sleep is seconds */
    }

exit:
    fprintf(stderr, "Clossing the application ...\n");
    close(sock);

    return -1;
}