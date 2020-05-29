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
#define RECV_BUFF_SIZE      1024
#define ETHERTYPE_PTP       0x88F7
#define SOCKET_TIMEOUT_SEC  1

/********************************* TYPEDEFS ***********************************/
typedef enum
{
    EXE_NAME = 0,
    INTERFACE,
    MODE,
    ARGUMENTS_N
} ptpArguments_t;

typedef enum
{
    PACKETS = 0,
    TIMESTAMPS,
    MODES_N
} ptpMode_t;

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
int serverReceive(int sockfd, uint8_t *buffer, int buffer_len, int64_t *ts_out)
{
    char ctrl[2048];

    struct iovec iov = (struct iovec){.iov_base = buffer, .iov_len = buffer_len};

    struct msghdr msg = (struct msghdr){.msg_control = ctrl,
                                        .msg_controllen = sizeof ctrl,
                                        .msg_name = NULL,
                                        .msg_namelen = 0,
                                        .msg_iov = &iov,
                                        .msg_iovlen = 1};

    int recv_len = recvmsg(sockfd, &msg, 0);

    if (recv_len < 0)
    {
        fprintf(stderr, "recvfrom failed: %d %s\n", recv_len, strerror(errno));
        // We didn't receive anything, that's okay because socket has a timeout
    }
    else
    {
        // Got a packet, get the timestamp, but default to -1 in case there was none
        *ts_out = -1;

        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg;
            cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
          fprintf(stdout, "level=%d, type=%d, len=%zu\n", cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len);

            //if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == IP_RECVERR))
            //{
            //  struct sock_extended_err *ext = (struct sock_extended_err *) CMSG_DATA(cmsg);
            //  printf("errno=%d, origin=%d\n", ext->ee_errno, ext->ee_origin);
            //}

            if (cmsg->cmsg_level == SOL_SOCKET)
            {
                if ((cmsg->cmsg_type == SO_TIMESTAMPNS) ||
                    (cmsg->cmsg_type == SO_TIMESTAMPING))
                {
                    // That's what we where looking for
                    struct scm_timestamping *ts = (struct scm_timestamping *) CMSG_DATA(cmsg);

                    *ts_out = (int64_t)(ts->ts[2].tv_sec) * 1000000000 + (int64_t)(ts->ts[2].tv_nsec);
                    fprintf(stdout, "%ld\n", *ts_out);

                    break;
                }
            }
        }
    }

    return recv_len;
}


static
int ptpPacket(uint8_t *recvbuf)
{
    struct pkt_ptp *pkt = NULL;
    struct ether_header *eh = NULL;
    int recv_len = -1;

    pkt = (struct pkt_ptp *)recvbuf;
    eh = &pkt->eh;

    /* Just a confirmation that we have received PTP packet */
    fprintf(stdout, "PTP packet received: ns:%d\n", ntohl(pkt->ns));

    return recv_len;
}

/***************************** MAIN **********************************/
int main(int argc, char *argv[])
{
    if (ARGUMENTS_N != argc) {
       fprintf(stdout, "usage: ./listener [interface] [mode]\n");
       fprintf(stdout, "(e.g. `listener eth1 ts` - get timestamps)\n");
       fprintf(stdout, "(e.g. `listener eth1 pkts` - print confirmation on every received ptp packet)\n");

       return -1;
    }

    const uint8_t *interface = argv[INTERFACE];
    const uint8_t *modeStr =  argv[MODE];
    ptpMode_t mode = TIMESTAMPS;

    uint8_t receiveBuffer[RECV_BUFF_SIZE];
    int recvLen = 0;

    int64_t ts_out = 0;

    int sock = -1;

    struct ifreq if_idx;
    struct sockaddr_ll socket_address;
    int socket_addressSize = 0;

    if (strcmp(modeStr, "ts") == 0)
    {
        mode = TIMESTAMPS;
    }
    else if (strcmp(modeStr, "pkts") == 0)
    {
        mode = PACKETS;
    }
    else
    {
        fprintf(stdout, "Default mode: timestamping.\n");
        mode = TIMESTAMPS;
    }

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_PTP));
    if (sock < 0)
    {
        fprintf(stderr, "Failed to create the socket! %s\n", strerror(errno));
        return 1;
    }
    else
    {
        fprintf(stdout, "Socket created ...\n");
    }

    if ( mode == TIMESTAMPS)
    {
        int timestampOn =
              SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE |
              SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_HARDWARE |
              SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE |
              // SOF_TIMESTAMPING_OPT_TSONLY |
              0;

        /* Enable timestamping */
        if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &timestampOn, sizeof timestampOn) < 0)
        {
            fprintf(stderr, "Failed to enable timestamping! %s\n",  strerror(errno));
            goto exit;
        }
    }

    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) < 0)
    {
        fprintf(stderr,  "Setup UDP server: setsockopt failed: %s\n", strerror(errno));
        goto exit;
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

    struct timeval tv;
    tv.tv_sec = SOCKET_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        fprintf(stderr, "Setup UDP server: setsockopt3 failed: %s\n", strerror(errno));
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
    socket_address.sll_protocol = ETHERTYPE_PTP;
    socket_address.sll_hatype   = ARPHRD_VOID;
    //socket_address.sll_pkttype  = PACKET_MULTICAST;
    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;

    socket_addressSize = sizeof(socket_address);

    while(1)
    {
        memset(receiveBuffer, 0, sizeof(receiveBuffer));

        if (mode == TIMESTAMPS)
        {
            recvLen = serverReceive(sock, receiveBuffer, RECV_BUFF_SIZE, &ts_out);
            dump_payload(receiveBuffer, recvLen);

        }
        else if (mode == PACKETS)
        {
            recvLen = recvfrom(sock, (char *)receiveBuffer, sizeof(receiveBuffer), 0,
                               (struct sockaddr *)&socket_address, &socket_addressSize);
            if (recvLen < 0)
            {
                printf("packet receive error.");
            }
            else
            {
                ptpPacket(receiveBuffer);
            }
        }
   }

exit:
    fprintf(stderr, "Clossing the application ...\n");
    close(sock);

    return -1;
}