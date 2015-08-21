#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define UDP_HDR_LEN 8

#define DIVERT_MINPORT 1LL
#define DIVERT_MAXPORT UINT16_MAX

#define PFD_IPV4 0
#define PFD_IPV6 1
#define POLL_FDS 2

// SIGALRM frequency
#define TICK_MS 997*997

struct packet_stash {
    ssize_t nbytes;
    uint8_t *packet;
};

bool corrupt_v4(uint8_t * packet, ssize_t nbytes, struct ip *ip4_hdr,
                uint32_t * hlen, ssize_t * range);
bool corrupt_v6(uint8_t * packet, ssize_t nbytes, struct ip6_hdr *ip6_hdr,
                uint32_t * hlen, ssize_t * range);
void emit_help(void);
// from goptfoo
double flagtod(const int flag, const char *flagarg, const double min,
               const double max);
void sig_handle(int sig);
