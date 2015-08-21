/*
 * OpenBSD divert(4) packet mangler. Supports (pseudo)random drops,
 * delay (and if so possibly also duplication), and data payload
 * corruption. See README for compiling and usage notes and
 * diversion.8 for additional documentation.
 */

#include "diversion.h"

#define FATED_TO(x) ((arc4random() / (double) UINT32_MAX) < x)

bool Flag_Corrupt_All;          // -a
double Flag_Corrupt;            // -C
uint8_t Flag_Corrupt_Count;     // -c
bool Flag_Debug;                // -d
int Flag_Direction;             // -f
double Flag_Drop;               // -D
double Flag_Delay;              // -W
double Flag_Duplicate;          // -R
bool Flag_Scrub_Mem;            // -s
char *Flag_User;                // -u

uint16_t Divert_Port;

struct packet_stash v4stash, v6stash;

volatile sig_atomic_t Sig_Flush;
volatile sig_atomic_t Sig_Terminate;

int main(int argc, char *argv[])
{
    int ch;
    const char *errstr;

    struct passwd *pw;

    sigset_t blockmask;

    int nfds;
    struct pollfd pfd[POLL_FDS];

    int fd4;
    socklen_t sin4_len;
    struct ip *ip4_hdr;
    struct sockaddr_in sin4;
    uint32_t hlen;

    int fd6;
    socklen_t sin6_len;
    struct ip6_hdr *ip6_hdr;
    struct sockaddr_in6 sin6;

    ssize_t nbytes;
    uint8_t packet[IP_MAXPACKET];
    ssize_t range;

    while ((ch = getopt(argc, argv, "h?C:D:R:W:c:df:su:")) != -1) {
        switch (ch) {
        case 'C':
            Flag_Corrupt = flagtod(ch, optarg, 0.0, 1.0);
            break;
        case 'D':
            Flag_Drop = flagtod(ch, optarg, 0.0, 1.0);
            break;
        case 'R':
            Flag_Duplicate = flagtod(ch, optarg, 0.0, 1.0);
            break;
        case 'W':
            Flag_Delay = flagtod(ch, optarg, 0.0, 1.0);
            break;
        case 'a':
            Flag_Corrupt_All = true;
            break;
        case 'c':
            if ((Flag_Corrupt_Count =
                 (uint8_t) strtonum(optarg, 1LL, (long long) UINT8_MAX,
                                    &errstr)) == 0) {
                if (errstr)
                    err(EX_DATAERR, "could not parse -c flag");
            }
            break;
        case 'd':
            Flag_Debug = true;
            break;
        case 'f':
            if ((Flag_Direction = strtonum(optarg, 0LL, 2LL, &errstr)) == 0) {
                if (errstr)
                    err(EX_DATAERR, "could not parse -f flag");
            } else {
                Flag_Direction = (Flag_Direction == 1)
                    ? IPPROTO_DIVERT_INIT : IPPROTO_DIVERT_RESP;
            }
            break;
        case 's':
            Flag_Scrub_Mem = true;
            break;
        case 'u':
            Flag_User = optarg;
            break;
        case 'h':
        case '?':
        default:
            emit_help();
            /* NOTREACHED */
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 1)
        emit_help();

    if ((Divert_Port =
         (uint16_t) strtonum(*argv, DIVERT_MINPORT, (long long) DIVERT_MAXPORT,
                             &errstr)) == 0) {
        if (errstr)
            err(EX_DATAERR, "could not parse divert port number");
    }

    if (geteuid())
        errx(EX_USAGE, "must be run as root");

    if (Flag_Corrupt) {
        if (Flag_Corrupt_Count == 0)
            Flag_Corrupt_Count = 1;
    }

    /* IPv4 setup */
    if ((fd4 = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1)
        err(EX_OSERR, "socket() failed for IPv4");
    if (Flag_Direction) {
        if (setsockopt
            (fd4, IPPROTO_IP, IP_DIVERTFL, &Flag_Direction,
             (socklen_t) sizeof(Flag_Direction)) == -1)
            err(EX_OSERR, "setsockopt() -f failed for IPv4");
    }

    explicit_bzero(&sin4, sizeof(sin4));
    sin4.sin_family = AF_INET;
    sin4.sin_port = htons(Divert_Port);
    sin4.sin_addr.s_addr = 0;

    sin4_len = sizeof(struct sockaddr_in);

    if (bind(fd4, (struct sockaddr *) &sin4, sin4_len) == -1)
        err(EX_OSERR, "bind() failed for IPv4");

    v4stash.packet = NULL;

    /* IPv6 setup */
    if ((fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_DIVERT)) == -1)
        err(EX_OSERR, "socket() failed for IPv6");
    if (Flag_Direction) {
        if (setsockopt
            (fd6, IPPROTO_IPV6, IP_DIVERTFL, &Flag_Direction,
             (socklen_t) sizeof(Flag_Direction)) == -1)
            err(EX_OSERR, "setsockopt() -f failed for IPv6");
    }

    explicit_bzero(&sin6, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_len = sizeof(struct sockaddr_in6);
    sin6.sin6_port = htons(Divert_Port);

    sin6_len = sizeof(struct sockaddr_in6);

    if (bind(fd6, (struct sockaddr *) &sin6, sin6.sin6_len) == -1)
        err(EX_OSERR, "bind() failed for IPv6");

    v6stash.packet = NULL;


    if (Flag_User) {
        if ((pw = getpwnam(Flag_User)) == NULL)
            err(EX_OSERR, "getpwnam() for -u user failed");
        if (chroot(pw->pw_dir) == -1)
            err(EX_OSERR, "chroot() failed");
        if (chdir("/") == -1)
            err(EX_OSERR, "chdir(\"/\") failed");
        if (setgroups(1, &pw->pw_gid) ||
            setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
            setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
            errx(EX_OSERR, "could not drop privileges");
    }

    if (!Flag_Debug) {
        if (daemon(1, 1) == -1)
            err(EX_OSERR, "daemon() call failed");
    }

    signal(SIGALRM, sig_handle);
    signal(SIGINT, sig_handle);
    signal(SIGTERM, sig_handle);
    ualarm(TICK_MS, TICK_MS);

    sigemptyset(&blockmask);
    sigaddset(&blockmask, SIGALRM);
    sigaddset(&blockmask, SIGINT);
    sigaddset(&blockmask, SIGTERM);

    explicit_bzero(&pfd, sizeof(pfd));
    pfd[PFD_IPV4].fd = fd4;
    pfd[PFD_IPV4].events = POLLIN;
    pfd[PFD_IPV6].fd = fd6;
    pfd[PFD_IPV6].events = POLLIN;

    for (;;) {
        if ((nfds = poll(pfd, POLL_FDS, -1)) == -1) {
            if (errno != EINTR)
                err(EX_OSERR, "poll() failed");
        }

        /* flush any delayed and bail out */
        if (Sig_Terminate) {
            sigprocmask(SIG_BLOCK, &blockmask, NULL);
            if (v4stash.packet) {
                if (sendto
                    (fd4, v4stash.packet, (size_t) v4stash.nbytes, 0,
                     (struct sockaddr *) &sin4, sin4_len) == -1)
                    if (Flag_Debug)
                        warn("IPv4 sendto() failed");
                if (Flag_Scrub_Mem)
                    explicit_bzero(v4stash.packet, (size_t) v4stash.nbytes);
                free(v4stash.packet);
                v4stash.packet = NULL;
            }
            if (v6stash.packet) {
                if (sendto
                    (fd6, v6stash.packet, (size_t) v6stash.nbytes, 0,
                     (struct sockaddr *) &sin6, sin6_len) == -1)
                    if (Flag_Debug)
                        warn("IPv6 sendto() failed");
                if (Flag_Scrub_Mem)
                    explicit_bzero(v6stash.packet, (size_t) v6stash.nbytes);
                free(v6stash.packet);
                v6stash.packet = NULL;
            }
            if (Flag_Scrub_Mem)
                explicit_bzero(packet, (size_t) IP_MAXPACKET);
            exit(1);
        }

        if (nfds > 0 && pfd[PFD_IPV4].revents & POLLIN) {
            range = -1;
            explicit_bzero(packet, sizeof(packet));

            if ((nbytes =
                 recvfrom(fd4, packet, sizeof(packet), 0,
                          (struct sockaddr *) &sin4, &sin4_len)) == -1) {
                if (Flag_Debug)
                    warn("IPv4 recvfrom() error");
                continue;
            }
            if (nbytes < (ssize_t) sizeof(struct ip)) {
                if (Flag_Debug)
                    warnx("IPv4 packet is too short");
                continue;
            }

            ip4_hdr = (struct ip *) packet;
            hlen = ip4_hdr->ip_hl << 2;
            if (hlen < sizeof(struct ip) || ntohs(ip4_hdr->ip_len) < hlen
                || nbytes < ntohs(ip4_hdr->ip_len)) {
                if (Flag_Debug)
                    warnx("invalid IPv4 packet");
                continue;
            }

            /* IPv4 decision */
            if (Flag_Delay && FATED_TO(Flag_Delay)) {
                if (!v4stash.packet) {
                    v4stash.nbytes = nbytes;
                    if ((v4stash.packet = malloc((size_t) nbytes)) == NULL) {
                        if (Flag_Debug)
                            warn("could not malloc() stash for IPv4 packet");
                    } else {
                        bcopy(packet, v4stash.packet, (size_t) nbytes);
                    }

                    if (Flag_Corrupt) {
                        if (!corrupt_v4
                            (v4stash.packet, nbytes, ip4_hdr, &hlen, &range))
                            continue;
                    }
                }

                if (Flag_Duplicate && !FATED_TO(Flag_Duplicate)) {
                    continue;
                }
            } else if (Flag_Drop && FATED_TO(Flag_Drop)) {
                continue;
            }

            if (Flag_Corrupt) {
                if (!corrupt_v4(packet, nbytes, ip4_hdr, &hlen, &range))
                    continue;
            }

            if (sendto
                (fd4, packet, (size_t) nbytes, 0, (struct sockaddr *) &sin4,
                 sin4_len) == -1)
                if (Flag_Debug)
                    warn("IPv4 sendto() failed");
        }

        if (nfds > 0 && pfd[PFD_IPV6].revents & POLLIN) {
            range = -1;
            explicit_bzero(packet, sizeof(packet));

            if ((nbytes =
                 recvfrom(fd6, packet, sizeof(packet), 0,
                          (struct sockaddr *) &sin6, &sin6_len)) == -1) {
                if (Flag_Debug)
                    warn("IPv6 recvfrom() error");
                continue;
            }
            if (nbytes < (ssize_t) sizeof(struct ip6_hdr)) {
                if (Flag_Debug)
                    warnx("IPv6 packet is too short");
                continue;
            }
            ip6_hdr = (struct ip6_hdr *) packet;
            hlen = ntohs(ip6_hdr->ip6_plen);
            if (hlen == 0) {
                if (Flag_Debug)
                    warnx("discarding unsupported IPv6 jumbo packet");
                continue;
            }
            if (hlen > nbytes) {
                if (Flag_Debug)
                    warnx("invalid IPv6 packet");
                continue;
            }

            /* IPv6 decision */
            if (Flag_Delay && FATED_TO(Flag_Delay)) {
                if (!v6stash.packet) {
                    v6stash.nbytes = nbytes;
                    if ((v6stash.packet = malloc((size_t) nbytes)) == NULL) {
                        if (Flag_Debug)
                            warn("could not malloc() stash for IPv6 packet");
                    } else {
                        bcopy(packet, v6stash.packet, (size_t) nbytes);
                    }

                    if (Flag_Corrupt) {
                        if (!corrupt_v6
                            (v6stash.packet, nbytes, ip6_hdr, &hlen, &range))
                            continue;
                    }
                }

                if (Flag_Duplicate && !FATED_TO(Flag_Duplicate)) {
                    continue;
                }
            } else if (Flag_Drop && FATED_TO(Flag_Drop)) {
                continue;
            }

            if (Flag_Corrupt) {
                if (!corrupt_v6(packet, nbytes, ip6_hdr, &hlen, &range))
                    continue;
            }

            if (sendto
                (fd6, packet, (size_t) nbytes, 0, (struct sockaddr *) &sin6,
                 sin6_len) == -1)
                if (Flag_Debug)
                    warn("IPv6 sendto() failed");
        }

        if (Sig_Flush) {
            if (v4stash.packet) {
                if (sendto
                    (fd4, v4stash.packet, (size_t) v4stash.nbytes, 0,
                     (struct sockaddr *) &sin4, sin4_len) == -1)
                    if (Flag_Debug)
                        warn("IPv4 sendto() failed");
                if (Flag_Scrub_Mem)
                    explicit_bzero(v4stash.packet, (size_t) v4stash.nbytes);
                free(v4stash.packet);
                v4stash.packet = NULL;
            }
            if (v6stash.packet) {
                if (sendto
                    (fd6, v6stash.packet, (size_t) v6stash.nbytes, 0,
                     (struct sockaddr *) &sin6, sin6_len) == -1)
                    if (Flag_Debug)
                        warn("IPv6 sendto() failed");
                if (Flag_Scrub_Mem)
                    explicit_bzero(v6stash.packet, (size_t) v6stash.nbytes);
                free(v6stash.packet);
                v6stash.packet = NULL;
            }
            Sig_Flush = 0;
        }
    }

    exit(1);                    /* NOTREACHED */
}

bool corrupt_v4(uint8_t * packet, ssize_t nbytes, struct ip *ip4_hdr,
                uint32_t * hlen, ssize_t * range)
{
    struct tcphdr *th;
    uint32_t tcphlen;

    if (Flag_Corrupt_All) {
        *hlen = 0;
        *range = nbytes;
    } else if (*range == -1) {
        // TODO probably incomplete and not very tested for correctness
        switch (ip4_hdr->ip_p) {
        case IPPROTO_TCP:
            th = (struct tcphdr *) (packet + *hlen);
            tcphlen = th->th_off << 2;
            if (tcphlen < 20) {
                if (Flag_Debug)
                    warnx("IPv4 TCP header len < 20 ??");
                return false;
            }
            *hlen += tcphlen;
            break;
        case IPPROTO_UDP:
            *hlen += UDP_HDR_LEN;
            break;
        }
        *range = nbytes - *hlen;
    }
    if (*range > 0) {
        for (uint8_t i = 0; i < Flag_Corrupt_Count; i++) {
            if (FATED_TO(Flag_Corrupt)) {
                packet[*hlen + arc4random_uniform((uint32_t) * range)] ^=
                    1 << arc4random_uniform((uint32_t) CHAR_BIT);
            }
        }
    }
    return true;
}

bool corrupt_v6(uint8_t * packet, ssize_t nbytes, struct ip6_hdr * ip6_hdr,
                uint32_t * hlen, ssize_t * range)
{
    uint8_t nexthdr;
    struct tcphdr *th;
    uint32_t tcphlen;
    uint32_t offset;
    bool more_hdrs = true;

    if (Flag_Corrupt_All) {
        *hlen = 0;
        *range = nbytes;
    } else if (*range == -1) {
        /* NOTE hlen begins as the IPv6 payload length, but after this
         * calculation should be the offset of where the data payload
         * begins, assuming all goes well. */
        offset = nbytes - *hlen;

        // TODO need code to walk the next headers...
        // see RFC 2460, 2402, 2406 for details on the extension headers
        nexthdr = ip6_hdr->ip6_nxt;
        while (more_hdrs) {
            switch (nexthdr) {
            //case 0:            // Hop-by-Hop Options header
            //    break;
            case IPPROTO_TCP:
                th = (struct tcphdr *) (packet + offset);
                tcphlen = th->th_off << 2;
                if (tcphlen < 20) {
                    if (Flag_Debug)
                        warnx("IPv6 TCP header len < 20 ??");
                    return false;
                }
                offset += tcphlen;
                more_hdrs = false;
                break;
            case IPPROTO_UDP:
                offset += UDP_HDR_LEN;
                more_hdrs = false;
                break;
            default:
                // NOTE will corrupt more than just data payload
                if (Flag_Debug)
                    warnx("unimplemented IPv6 next header %u", nexthdr);
                more_hdrs = false;
            }
        }

        warnx("dbg v6 nbytes=%lld hlen=%lld", nbytes, *hlen);
        for (int i = offset; i < nbytes; i++) {
            fprintf(stderr, "%.2x", packet[i]);
        }
        putchar('\n');

        *hlen = offset;
        *range = nbytes - *hlen;
    }
    if (*range > 0) {
        for (uint8_t i = 0; i < Flag_Corrupt_Count; i++) {
            if (FATED_TO(Flag_Corrupt)) {
                packet[*hlen + arc4random_uniform((uint32_t) * range)] ^=
                    1 << arc4random_uniform((uint32_t) CHAR_BIT);
            }
        }
    }
    return true;
}

void emit_help(void)
{
    fprintf(stderr, "Usage: diversion [options] divert-port\n"
            "  -C corrupt odds (0.0 to 1.0)\n"
            "  -D drop odds\n"
            "  -R duplicate odds (if delayed)\n"
            "  -W delay odds\n"
            "  -f [012] direction of match (0=both,1=INIT,2=RESP)\n"
            "  -a corrupt all of the packet, not just data payload\n"
            "  -d debug, do not daemonize\n"
            "  -s scrubs memory if set\n"
            "  -u user  to drop privs to\n"
            "\n" "divert-port requires pf.conf configuration\n");
    exit(EX_USAGE);
}

// borrowed from goptfoo to reduce library deps
double flagtod(const int flag, const char *flagarg, const double min,
               const double max)
{
    char *ep;
    double val;

    if (!flagarg || *flagarg == '\0')
        errx(EX_DATAERR, "flag argument not set for -%c", flag);

    errno = 0;
    val = strtod(flagarg, &ep);
    if (flagarg[0] == '\0' || *ep != '\0')
        errx(EX_DATAERR, "could not parse double from -%c '%s'", flag, flagarg);
    if (errno == ERANGE)
        errx(EX_DATAERR, "value for -%c '%s' is not a double", flag, flagarg);
    // TODO -Wconversion warnings from these isfinite calls
    if (isfinite((double) min) && val < min)
        errx(EX_DATAERR, "value for -%c '%s' is below min %.2f", flag, flagarg,
             min);
    if (isfinite((double) max) && val > max)
        errx(EX_DATAERR, "value for -%c '%s' exceeds max %.2f", flag, flagarg,
             max);
    return val;
}

void sig_handle(int sig)
{
    switch (sig) {
    case SIGALRM:
        Sig_Flush = 1;
        break;
    case SIGINT:
    case SIGTERM:
        Sig_Terminate = 1;
        break;
    }
}
