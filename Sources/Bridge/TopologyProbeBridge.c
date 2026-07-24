#include "TopologyProbeBridge.h"

#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#if __has_include(<net/route.h>)
#include <net/route.h>
#endif

#if __has_include(<sys/kern_event.h>)
#include <sys/kern_event.h>
#endif

#if TARGET_OS_OSX
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#endif

#ifndef RTF_LLINFO
#define RTF_LLINFO 0x400
#endif

#ifndef NET_RT_DUMP2
#define NET_RT_DUMP2 7
#endif

#ifndef RTAX_DST
#define RTAX_DST 0
#endif

#ifndef RTAX_GATEWAY
#define RTAX_GATEWAY 1
#endif

#ifndef RTAX_MAX
#define RTAX_MAX 8
#endif

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} TEPBuffer;

typedef struct {
    uint32_t address;
    uint32_t mask;
    char name[IFNAMSIZ];
    bool found;
} TEPIPv4Selection;

typedef struct {
    uint32_t rmx_locks;
    uint32_t rmx_mtu;
    uint32_t rmx_hopcount;
    int32_t rmx_expire;
    uint32_t rmx_recvpipe;
    uint32_t rmx_sendpipe;
    uint32_t rmx_ssthresh;
    uint32_t rmx_rtt;
    uint32_t rmx_rttvar;
    uint32_t rmx_pksent;
    uint32_t rmx_filler[4];
} TEPRTMetrics;

typedef struct {
    unsigned short rtm_msglen;
    unsigned char rtm_version;
    unsigned char rtm_type;
    unsigned short rtm_index;
    int rtm_flags;
    int rtm_addrs;
    pid_t rtm_pid;
    int rtm_seq;
    int rtm_errno;
    int rtm_use;
    uint32_t rtm_inits;
    TEPRTMetrics rtm_rmx;
} TEPRTMessageHeader;

typedef struct {
    int listener;
    int client;
    int accepted;
    int udp;
} TEPTestSockets;

typedef struct {
    int fd;
    int discardedDatagrams;
} TEPRouteEventCapture;

/*
 * The iOS device SDK does not ship <sys/kern_control.h>, even though the
 * underlying PF_SYSTEM control ABI is present. These layouts and constants
 * match Apple's public macOS SDK. The Network Statistics messages below match
 * Apple's open-source xnu/bsd/net/ntstat.h.
 */
#ifndef SYSPROTO_CONTROL
#define SYSPROTO_CONTROL 2
#endif

#ifndef AF_SYS_CONTROL
#define AF_SYS_CONTROL 2
#endif

#define TEP_MAX_KCTL_NAME 96

typedef struct {
    uint32_t ctl_id;
    char ctl_name[TEP_MAX_KCTL_NAME];
} TEPControlInfo;

typedef struct {
    unsigned char sc_len;
    unsigned char sc_family;
    uint16_t ss_sysaddr;
    uint32_t sc_id;
    uint32_t sc_unit;
    uint32_t sc_reserved[5];
} TEPSockaddrControl;

#define TEP_CTLIOCGINFO _IOWR('N', 3, TEPControlInfo)

enum {
    TEP_NSTAT_MSG_SUCCESS = 0,
    TEP_NSTAT_MSG_ERROR = 1,
    TEP_NSTAT_MSG_ADD_ALL_SRCS = 1002,
    TEP_NSTAT_MSG_GET_UPDATE = 1007,
    TEP_NSTAT_MSG_SRC_ADDED = 10001,
    TEP_NSTAT_MSG_SRC_REMOVED = 10002,
    TEP_NSTAT_MSG_SRC_DESC = 10003,
    TEP_NSTAT_MSG_SRC_COUNTS = 10004,
    TEP_NSTAT_MSG_SYSINFO_COUNTS = 10005,
    TEP_NSTAT_MSG_SRC_UPDATE = 10006,
    TEP_NSTAT_MSG_SRC_EXTENDED_UPDATE = 10007,
    TEP_NSTAT_MSG_SRC_DETAILS = 10008,
    TEP_NSTAT_MSG_SRC_EXTENDED_DETAILS = 10009,
};

enum {
    TEP_NSTAT_PROVIDER_ROUTE = 1,
    TEP_NSTAT_PROVIDER_TCP_KERNEL = 2,
    TEP_NSTAT_PROVIDER_TCP_USERLAND = 3,
    TEP_NSTAT_PROVIDER_UDP_KERNEL = 4,
    TEP_NSTAT_PROVIDER_UDP_USERLAND = 5,
    TEP_NSTAT_PROVIDER_IFNET = 6,
    TEP_NSTAT_PROVIDER_QUIC_USERLAND = 8,
    TEP_NSTAT_PROVIDER_CONN_USERLAND = 9,
    TEP_NSTAT_PROVIDER_UDP_SUBFLOW = 10,
};

typedef struct {
    uint64_t context __attribute__((aligned(sizeof(uint64_t))));
    uint32_t type;
    uint16_t length;
    uint16_t flags;
} TEPNstatMessageHeader;

typedef struct {
    TEPNstatMessageHeader header;
    uint64_t filter __attribute__((aligned(sizeof(uint64_t))));
    uint64_t events __attribute__((aligned(sizeof(uint64_t))));
    uint32_t provider;
    pid_t targetPID;
    unsigned char targetUUID[16];
} TEPNstatAddAllSources;

typedef struct {
    TEPNstatMessageHeader header;
    uint64_t sourceReference __attribute__((aligned(sizeof(uint64_t))));
} TEPNstatQuerySources;

typedef struct {
    uint64_t rxPackets __attribute__((aligned(sizeof(uint64_t))));
    uint64_t rxBytes;
    uint64_t txPackets;
    uint64_t txBytes;
    uint64_t cellularRxBytes;
    uint64_t cellularTxBytes;
    uint64_t wifiRxBytes;
    uint64_t wifiTxBytes;
    uint64_t wiredRxBytes;
    uint64_t wiredTxBytes;
    uint32_t duplicateRxBytes;
    uint32_t outOfOrderRxBytes;
    uint32_t retransmittedTx;
    uint32_t connectionAttempts;
    uint32_t connectionSuccesses;
    uint32_t minimumRTT;
    uint32_t averageRTT;
    uint32_t RTTVariance;
} TEPNstatCounts;

typedef struct {
    TEPNstatMessageHeader header;
    uint64_t sourceReference __attribute__((aligned(sizeof(uint64_t))));
    uint64_t eventFlags __attribute__((aligned(sizeof(uint64_t))));
    TEPNstatCounts counts;
    uint32_t provider;
    unsigned char reserved[4];
} TEPNstatUpdatePrefix;

typedef struct {
    uint64_t uniquePID;
    uint64_t effectiveUniquePID;
    uint64_t startTimestamp;
    uint64_t timestamp;
    uint64_t rxTransferSize;
    uint64_t txTransferSize;
    uint64_t activityStart;
    uint64_t activityBitmap[2];
    uint32_t interfaceIndex;
    uint32_t state;
    uint32_t sendBufferSize;
    uint32_t sendBufferUsed;
    uint32_t receiveBufferSize;
    uint32_t receiveBufferUsed;
    uint32_t unacknowledgedBytes;
    uint32_t sendWindow;
    uint32_t congestionWindow;
    uint32_t trafficClass;
    uint32_t trafficManagementFlags;
    uint32_t pid;
    uint32_t effectivePID;
} TEPNstatTCPDescriptorPrefix;

typedef struct {
    int datagrams;
    int messages;
    int malformed;
    int success;
    int errors;
    int firstError;
    int sourceAdded;
    int sourceRemoved;
    int descriptions;
    int counts;
    int updates;
    int extendedUpdates;
    int details;
    int extendedDetails;
    int continuation;
    uint64_t rxPackets;
    uint64_t rxBytes;
    uint64_t txPackets;
    uint64_t txBytes;
    uint64_t wifiRxBytes;
    uint64_t wifiTxBytes;
    uint64_t wiredRxBytes;
    uint64_t wiredTxBytes;
    uint64_t cellularRxBytes;
    uint64_t cellularTxBytes;
    uint64_t connectionAttempts;
    uint64_t connectionSuccesses;
    uint64_t sourcePIDs[1024];
    int sourcePIDCount;
    int foreignPIDCount;
    int tcpStates[32];
} TEPNstatSummary;

_Static_assert(sizeof(TEPControlInfo) == 100, "Unexpected kernel-control info ABI");
_Static_assert(sizeof(TEPSockaddrControl) == 32, "Unexpected kernel-control address ABI");
_Static_assert(sizeof(TEPNstatMessageHeader) == 16, "Unexpected Network Statistics header ABI");
_Static_assert(sizeof(TEPNstatAddAllSources) == 56, "Unexpected Network Statistics add-all ABI");
_Static_assert(sizeof(TEPNstatQuerySources) == 24, "Unexpected Network Statistics query ABI");
_Static_assert(sizeof(TEPNstatCounts) == 112, "Unexpected Network Statistics counts ABI");
_Static_assert(sizeof(TEPNstatUpdatePrefix) == 152, "Unexpected Network Statistics update ABI");
_Static_assert(
    offsetof(TEPNstatTCPDescriptorPrefix, state) == 76,
    "Unexpected Network Statistics TCP descriptor state offset"
);
_Static_assert(
    offsetof(TEPNstatTCPDescriptorPrefix, pid) == 116,
    "Unexpected Network Statistics TCP descriptor PID offset"
);

static void TEPAppend(TEPBuffer *buffer, const char *format, ...) {
    if (buffer->capacity == 0) {
        buffer->capacity = 8192;
        buffer->data = calloc(buffer->capacity, 1);
    }

    while (buffer->data != NULL) {
        va_list args;
        va_start(args, format);
        int written = vsnprintf(
            buffer->data + buffer->length,
            buffer->capacity - buffer->length,
            format,
            args
        );
        va_end(args);

        if (written < 0) {
            return;
        }

        if (buffer->length + (size_t)written < buffer->capacity) {
            buffer->length += (size_t)written;
            return;
        }

        size_t nextCapacity = buffer->capacity * 2;
        char *nextData = realloc(buffer->data, nextCapacity);
        if (nextData == NULL) {
            free(buffer->data);
            buffer->data = NULL;
            buffer->length = 0;
            buffer->capacity = 0;
            return;
        }
        buffer->data = nextData;
        buffer->capacity = nextCapacity;
    }
}

static void TEPAppendMAC(TEPBuffer *buffer, const unsigned char *bytes, int count) {
    for (int index = 0; index < count; index++) {
        TEPAppend(buffer, "%s%02x", index == 0 ? "" : ":", bytes[index]);
    }
}

static void TEPAppendIPv4(TEPBuffer *buffer, uint32_t hostOrderAddress) {
    struct in_addr address = {.s_addr = htonl(hostOrderAddress)};
    char text[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &address, text, sizeof(text)) != NULL) {
        TEPAppend(buffer, "%s", text);
    } else {
        TEPAppend(buffer, "unknown");
    }
}

static int TEPIPv4PrefixLength(uint32_t mask) {
    int prefix = 0;
    for (int bit = 31; bit >= 0; bit--) {
        if ((mask & (1u << bit)) == 0) {
            break;
        }
        prefix++;
    }
    return prefix;
}

static size_t TEPSockaddrRoundup(size_t length) {
    return length > 0 ? (1 + ((length - 1) | (sizeof(long) - 1))) : sizeof(long);
}

static bool TEPMACIsAllZero(const unsigned char *bytes, int count) {
    for (int index = 0; index < count; index++) {
        if (bytes[index] != 0) {
            return false;
        }
    }
    return true;
}

static bool TEPMACIsPrivacyPlaceholder(const unsigned char *bytes, int count) {
    if (count != 6 || bytes[0] != 0x02) {
        return false;
    }
    for (int index = 1; index < count; index++) {
        if (bytes[index] != 0) {
            return false;
        }
    }
    return true;
}

static TEPIPv4Selection TEPAppendInterfaces(TEPBuffer *buffer) {
    TEPIPv4Selection selection = {0};
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) {
        TEPAppend(buffer, "interfaces.getifaddrs=error errno=%d message=%s\n", errno, strerror(errno));
        return selection;
    }

    int ipv4Count = 0;
    int ipv6Count = 0;
    int linkCount = 0;

    for (struct ifaddrs *cursor = interfaces; cursor != NULL; cursor = cursor->ifa_next) {
        if (cursor->ifa_addr == NULL || cursor->ifa_name == NULL) {
            continue;
        }

        sa_family_t family = cursor->ifa_addr->sa_family;
        if (family == AF_INET) {
            ipv4Count++;
            struct sockaddr_in *address = (struct sockaddr_in *)cursor->ifa_addr;
            struct sockaddr_in *netmask = (struct sockaddr_in *)cursor->ifa_netmask;
            uint32_t hostAddress = ntohl(address->sin_addr.s_addr);
            uint32_t hostMask = netmask == NULL ? 0 : ntohl(netmask->sin_addr.s_addr);

            char addressText[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &address->sin_addr, addressText, sizeof(addressText));
            TEPAppend(
                buffer,
                "interfaces.ipv4 name=%s address=%s flags=0x%x prefix=%d\n",
                cursor->ifa_name,
                addressText,
                cursor->ifa_flags,
                TEPIPv4PrefixLength(hostMask)
            );

            bool eligible = (cursor->ifa_flags & IFF_UP) != 0 &&
                (cursor->ifa_flags & IFF_LOOPBACK) == 0 &&
                hostAddress != 0 &&
                hostMask != 0;
            bool preferred = strcmp(cursor->ifa_name, "en0") == 0;
            if (eligible && (!selection.found || preferred)) {
                selection.address = hostAddress;
                selection.mask = hostMask;
                strlcpy(selection.name, cursor->ifa_name, sizeof(selection.name));
                selection.found = true;
            }
        } else if (family == AF_INET6) {
            ipv6Count++;
        } else if (family == AF_LINK) {
            linkCount++;
            struct sockaddr_dl *link = (struct sockaddr_dl *)cursor->ifa_addr;
            TEPAppend(
                buffer,
                "interfaces.link name=%s index=%hu type=%u alen=%u mac=",
                cursor->ifa_name,
                link->sdl_index,
                link->sdl_type,
                link->sdl_alen
            );
            if (link->sdl_alen > 0) {
                TEPAppendMAC(buffer, (const unsigned char *)LLADDR(link), link->sdl_alen);
            } else {
                TEPAppend(buffer, "none");
            }
            TEPAppend(buffer, "\n");
        }
    }

    freeifaddrs(interfaces);
    TEPAppend(
        buffer,
        "interfaces.summary ipv4=%d ipv6=%d link=%d selected=%s\n",
        ipv4Count,
        ipv6Count,
        linkCount,
        selection.found ? selection.name : "none"
    );
    return selection;
}

static const char *TEPRouteMessageTypeName(unsigned int type) {
    switch (type) {
#ifdef RTM_ADD
        case RTM_ADD: return "add";
#endif
#ifdef RTM_DELETE
        case RTM_DELETE: return "delete";
#endif
#ifdef RTM_CHANGE
        case RTM_CHANGE: return "change";
#endif
#ifdef RTM_GET
        case RTM_GET: return "get";
#endif
#ifdef RTM_LOSING
        case RTM_LOSING: return "losing";
#endif
#ifdef RTM_REDIRECT
        case RTM_REDIRECT: return "redirect";
#endif
#ifdef RTM_MISS
        case RTM_MISS: return "miss";
#endif
#ifdef RTM_LOCK
        case RTM_LOCK: return "lock";
#endif
#ifdef RTM_RESOLVE
        case RTM_RESOLVE: return "resolve";
#endif
#ifdef RTM_NEWADDR
        case RTM_NEWADDR: return "newaddr";
#endif
#ifdef RTM_DELADDR
        case RTM_DELADDR: return "deladdr";
#endif
#ifdef RTM_IFINFO
        case RTM_IFINFO: return "ifinfo";
#endif
#ifdef RTM_NEWMADDR
        case RTM_NEWMADDR: return "newmaddr";
#endif
#ifdef RTM_DELMADDR
        case RTM_DELMADDR: return "delmaddr";
#endif
#ifdef RTM_IFINFO2
        case RTM_IFINFO2: return "ifinfo2";
#endif
#ifdef RTM_NEWMADDR2
        case RTM_NEWMADDR2: return "newmaddr2";
#endif
        default: return "other";
    }
}

static TEPRouteEventCapture TEPBeginRouteEventCapture(TEPBuffer *buffer) {
    TEPRouteEventCapture capture = {
        .fd = -1,
        .discardedDatagrams = 0,
    };

    errno = 0;
    capture.fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    int socketError = errno;
    TEPAppend(
        buffer,
        "route_events.open result=%d errno=%d message=%s\n",
        capture.fd,
        socketError,
        socketError == 0 ? "none" : strerror(socketError)
    );
    if (capture.fd < 0) {
        return capture;
    }

    int flags = fcntl(capture.fd, F_GETFL, 0);
    errno = 0;
    int nonblockingResult = flags < 0
        ? -1
        : fcntl(capture.fd, F_SETFL, flags | O_NONBLOCK);
    int nonblockingError = errno;
    TEPAppend(
        buffer,
        "route_events.nonblocking result=%d errno=%d message=%s\n",
        nonblockingResult,
        nonblockingError,
        nonblockingError == 0 ? "none" : strerror(nonblockingError)
    );
    if (nonblockingResult != 0) {
        close(capture.fd);
        capture.fd = -1;
        return capture;
    }

    unsigned char discard[4096];
    while (recv(capture.fd, discard, sizeof(discard), MSG_DONTWAIT) > 0) {
        capture.discardedDatagrams++;
    }
    return capture;
}

static void TEPEndRouteEventCapture(
    TEPBuffer *buffer,
    TEPRouteEventCapture capture
) {
    if (capture.fd < 0) {
        TEPAppend(buffer, "route_events.summary status=unavailable\n");
        return;
    }

    unsigned char raw[64 * 1024];
    int datagrams = 0;
    int messages = 0;
    int malformed = 0;
    size_t bytes = 0;
    unsigned int typeCounts[256] = {0};
    int finalError = 0;

    for (int readIndex = 0; readIndex < 1024; readIndex++) {
        errno = 0;
        ssize_t received = recv(capture.fd, raw, sizeof(raw), MSG_DONTWAIT);
        if (received < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                finalError = errno;
            }
            break;
        }
        if (received == 0) {
            break;
        }

        datagrams++;
        bytes += (size_t)received;
        size_t offset = 0;
        while (offset + 4 <= (size_t)received) {
            unsigned short messageLength = 0;
            memcpy(&messageLength, raw + offset, sizeof(messageLength));
            if (messageLength < 4 || offset + messageLength > (size_t)received) {
                malformed++;
                break;
            }

            unsigned int type = raw[offset + 3];
            typeCounts[type]++;
            messages++;
            offset += messageLength;
        }
        if (offset != (size_t)received) {
            malformed++;
        }
    }

    close(capture.fd);
    TEPAppend(
        buffer,
        "route_events.summary discarded_before_warm=%d datagrams=%d messages=%d bytes=%zu malformed=%d errno=%d message=%s\n",
        capture.discardedDatagrams,
        datagrams,
        messages,
        bytes,
        malformed,
        finalError,
        finalError == 0 ? "none" : strerror(finalError)
    );
    for (int type = 0; type < 256; type++) {
        if (typeCounts[type] > 0) {
            TEPAppend(
                buffer,
                "route_events.type value=%d name=%s count=%u\n",
                type,
                TEPRouteMessageTypeName((unsigned int)type),
                typeCounts[type]
            );
        }
    }
}

static void TEPWarmNeighborCache(TEPBuffer *buffer, TEPIPv4Selection selection) {
    if (!selection.found) {
        TEPAppend(buffer, "neighbors.warm=skipped reason=no-active-ipv4-interface\n");
        return;
    }

    uint32_t network = selection.address & selection.mask;
    uint32_t broadcast = network | ~selection.mask;
    uint32_t hostCount = broadcast > network ? broadcast - network - 1 : 0;

    TEPAppend(buffer, "neighbors.warm interface=%s subnet=", selection.name);
    TEPAppendIPv4(buffer, network);
    TEPAppend(buffer, "/%d hosts=%u\n", TEPIPv4PrefixLength(selection.mask), hostCount);

    if (hostCount == 0 || hostCount > 1022) {
        TEPAppend(buffer, "neighbors.warm=skipped reason=host-count-limit hosts=%u\n", hostCount);
        return;
    }

    int socketFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socketFD < 0) {
        TEPAppend(buffer, "neighbors.warm=error stage=socket errno=%d message=%s\n", errno, strerror(errno));
        return;
    }

    const char payload = 0;
    int sent = 0;
    int firstError = 0;
    for (uint32_t host = network + 1; host < broadcast; host++) {
        if (host == selection.address) {
            continue;
        }

        struct sockaddr_in target = {0};
        target.sin_len = sizeof(target);
        target.sin_family = AF_INET;
        target.sin_port = htons(9);
        target.sin_addr.s_addr = htonl(host);
        errno = 0;
        if (sendto(
            socketFD,
            &payload,
            sizeof(payload),
            0,
            (struct sockaddr *)&target,
            sizeof(target)
        ) >= 0) {
            sent++;
        } else if (firstError == 0) {
            firstError = errno;
        }
    }

    close(socketFD);
    usleep(500000);
    TEPAppend(
        buffer,
        "neighbors.warm.result sent=%d first_errno=%d first_message=%s\n",
        sent,
        firstError,
        firstError == 0 ? "none" : strerror(firstError)
    );
}

static void TEPReadNeighbors(
    TEPBuffer *buffer,
    const char *label,
    int family,
    int operation
) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, family, operation, RTF_LLINFO};
    size_t needed = 0;
    errno = 0;
    int sizeResult = sysctl(mib, 6, NULL, &needed, NULL, 0);
    int sizeError = errno;
    TEPAppend(
        buffer,
        "neighbors.%s.size result=%d errno=%d message=%s bytes=%zu\n",
        label,
        sizeResult,
        sizeError,
        sizeError == 0 ? "none" : strerror(sizeError),
        needed
    );
    if (sizeResult != 0 || needed == 0) {
        return;
    }

    char *raw = malloc(needed);
    if (raw == NULL) {
        TEPAppend(buffer, "neighbors.%s.read=error reason=allocation bytes=%zu\n", label, needed);
        return;
    }

    errno = 0;
    int readResult = sysctl(mib, 6, raw, &needed, NULL, 0);
    int readError = errno;
    TEPAppend(
        buffer,
        "neighbors.%s.read result=%d errno=%d message=%s bytes=%zu\n",
        label,
        readResult,
        readError,
        readError == 0 ? "none" : strerror(readError),
        needed
    );
    if (readResult != 0) {
        free(raw);
        return;
    }

    int entryCount = 0;
    int macCount = 0;
    int zeroCount = 0;
    int placeholderCount = 0;
    int dynamicCount = 0;
    int staticCount = 0;
    int routerCount = 0;
    int proxyCount = 0;
    int rejectCount = 0;
    int interfaceScopedCount = 0;
    int expiringCount = 0;
    int usedCount = 0;
    unsigned short interfaceIndices[256] = {0};
    int interfaceCount = 0;
    int shown = 0;
    char *limit = raw + needed;
    for (char *next = raw; next < limit;) {
        TEPRTMessageHeader *header = (TEPRTMessageHeader *)next;
        if (header->rtm_msglen == 0 || next + header->rtm_msglen > limit) {
            break;
        }

        struct sockaddr *address = (struct sockaddr *)(header + 1);
        struct sockaddr *destination = NULL;
        struct sockaddr_dl *link = NULL;
        for (int bit = 0; bit < RTAX_MAX && (char *)address < next + header->rtm_msglen; bit++) {
            if ((header->rtm_addrs & (1 << bit)) != 0) {
                if (bit == RTAX_DST && address->sa_family == family) {
                    destination = address;
                } else if (bit == RTAX_GATEWAY && address->sa_family == AF_LINK) {
                    link = (struct sockaddr_dl *)address;
                }
                address = (struct sockaddr *)((char *)address + TEPSockaddrRoundup(address->sa_len));
            }
        }

        if (destination != NULL && link != NULL) {
            entryCount++;
#ifdef RTF_DYNAMIC
            dynamicCount += (header->rtm_flags & RTF_DYNAMIC) != 0;
#endif
#ifdef RTF_STATIC
            staticCount += (header->rtm_flags & RTF_STATIC) != 0;
#endif
#ifdef RTF_ROUTER
            routerCount += (header->rtm_flags & RTF_ROUTER) != 0;
#endif
#ifdef RTF_PROXY
            proxyCount += (header->rtm_flags & RTF_PROXY) != 0;
#endif
#ifdef RTF_REJECT
            rejectCount += (header->rtm_flags & RTF_REJECT) != 0;
#endif
#ifdef RTF_IFSCOPE
            interfaceScopedCount += (header->rtm_flags & RTF_IFSCOPE) != 0;
#endif
            expiringCount += header->rtm_rmx.rmx_expire != 0;
            usedCount += header->rtm_use != 0;

            bool interfaceSeen = false;
            for (int interfaceIndex = 0; interfaceIndex < interfaceCount; interfaceIndex++) {
                if (interfaceIndices[interfaceIndex] == link->sdl_index) {
                    interfaceSeen = true;
                    break;
                }
            }
            if (!interfaceSeen &&
                interfaceCount < (int)(sizeof(interfaceIndices) / sizeof(interfaceIndices[0]))) {
                interfaceIndices[interfaceCount++] = link->sdl_index;
            }

            const unsigned char *mac = (const unsigned char *)LLADDR(link);
            if (link->sdl_alen > 0) {
                macCount++;
                if (TEPMACIsAllZero(mac, link->sdl_alen)) {
                    zeroCount++;
                }
                if (TEPMACIsPrivacyPlaceholder(mac, link->sdl_alen)) {
                    placeholderCount++;
                }
            }

            if (shown < 32) {
                char ip[INET6_ADDRSTRLEN] = {0};
                const void *rawAddress = family == AF_INET
                    ? (const void *)&((struct sockaddr_in *)destination)->sin_addr
                    : (const void *)&((struct sockaddr_in6 *)destination)->sin6_addr;
                inet_ntop(family, rawAddress, ip, sizeof(ip));
                TEPAppend(
                    buffer,
                    "neighbors.%s.entry ip=%s alen=%u flags=0x%x use=%d expire=%d resolved=%s mac=",
                    label,
                    ip[0] == '\0' ? "unknown" : ip,
                    link->sdl_alen,
                    header->rtm_flags,
                    header->rtm_use,
                    header->rtm_rmx.rmx_expire,
                    link->sdl_alen > 0 ? "true" : "false"
                );
                if (link->sdl_alen > 0) {
                    TEPAppendMAC(buffer, mac, link->sdl_alen);
                } else {
                    TEPAppend(buffer, "none");
                }
                TEPAppend(buffer, "\n");
                shown++;
            }
        }
        next += header->rtm_msglen;
    }

    free(raw);
    TEPAppend(
        buffer,
        "neighbors.%s.summary entries=%d with_mac=%d all_zero=%d privacy_placeholder=%d interfaces=%d dynamic=%d static=%d router=%d proxy=%d reject=%d ifscope=%d expiring=%d used=%d shown=%d\n",
        label,
        entryCount,
        macCount,
        zeroCount,
        placeholderCount,
        interfaceCount,
        dynamicCount,
        staticCount,
        routerCount,
        proxyCount,
        rejectCount,
        interfaceScopedCount,
        expiringCount,
        usedCount,
        shown
    );
}

static void TEPReadRouteOperation(
    TEPBuffer *buffer,
    const char *label,
    int family,
    int operation,
    int argument
) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, family, operation, argument};
    size_t needed = 0;
    errno = 0;
    int sizeResult = sysctl(mib, 6, NULL, &needed, NULL, 0);
    int sizeError = errno;
    TEPAppend(
        buffer,
        "route.%s.size result=%d errno=%d message=%s bytes=%zu\n",
        label,
        sizeResult,
        sizeError,
        sizeError == 0 ? "none" : strerror(sizeError),
        needed
    );
    if (sizeResult != 0 || needed == 0) {
        return;
    }

    char *raw = malloc(needed);
    if (raw == NULL) {
        TEPAppend(buffer, "route.%s.read=error reason=allocation bytes=%zu\n", label, needed);
        return;
    }

    errno = 0;
    int readResult = sysctl(mib, 6, raw, &needed, NULL, 0);
    int readError = errno;
    TEPAppend(
        buffer,
        "route.%s.read result=%d errno=%d message=%s bytes=%zu\n",
        label,
        readResult,
        readError,
        readError == 0 ? "none" : strerror(readError),
        needed
    );
    if (readResult == 0 && (operation == NET_RT_DUMP || operation == NET_RT_DUMP2)) {
        int entries = 0;
        int up = 0;
        int gateway = 0;
        int host = 0;
        int llinfo = 0;
        int dynamic = 0;
        int modified = 0;
        int routeStatic = 0;
        int blackhole = 0;
        int reject = 0;
        int local = 0;
        int broadcast = 0;
        int multicast = 0;
        int ifscope = 0;
        int proxy = 0;
        int router = 0;
        int global = 0;
        int expiring = 0;
        int mtu = 0;
        int rtt = 0;
        int packetsSent = 0;
        uint64_t totalUses = 0;
        uint64_t totalPacketsSent = 0;
        unsigned short interfaceIndices[256] = {0};
        int interfaceCount = 0;
        char *limit = raw + needed;
        for (char *next = raw; next < limit;) {
            TEPRTMessageHeader *header = (TEPRTMessageHeader *)next;
            if (header->rtm_msglen == 0 || next + header->rtm_msglen > limit) {
                break;
            }
            entries++;
            up += (header->rtm_flags & 0x1) != 0;
            gateway += (header->rtm_flags & 0x2) != 0;
            host += (header->rtm_flags & 0x4) != 0;
            dynamic += (header->rtm_flags & 0x10) != 0;
            modified += (header->rtm_flags & 0x20) != 0;
            llinfo += (header->rtm_flags & RTF_LLINFO) != 0;
#ifdef RTF_STATIC
            routeStatic += (header->rtm_flags & RTF_STATIC) != 0;
#endif
#ifdef RTF_BLACKHOLE
            blackhole += (header->rtm_flags & RTF_BLACKHOLE) != 0;
#endif
#ifdef RTF_REJECT
            reject += (header->rtm_flags & RTF_REJECT) != 0;
#endif
#ifdef RTF_LOCAL
            local += (header->rtm_flags & RTF_LOCAL) != 0;
#endif
#ifdef RTF_BROADCAST
            broadcast += (header->rtm_flags & RTF_BROADCAST) != 0;
#endif
#ifdef RTF_MULTICAST
            multicast += (header->rtm_flags & RTF_MULTICAST) != 0;
#endif
#ifdef RTF_IFSCOPE
            ifscope += (header->rtm_flags & RTF_IFSCOPE) != 0;
#endif
#ifdef RTF_PROXY
            proxy += (header->rtm_flags & RTF_PROXY) != 0;
#endif
#ifdef RTF_ROUTER
            router += (header->rtm_flags & RTF_ROUTER) != 0;
#endif
#ifdef RTF_GLOBAL
            global += (header->rtm_flags & RTF_GLOBAL) != 0;
#endif
            expiring += header->rtm_rmx.rmx_expire != 0;
            mtu += header->rtm_rmx.rmx_mtu != 0;
            rtt += header->rtm_rmx.rmx_rtt != 0;
            packetsSent += header->rtm_rmx.rmx_pksent != 0;
            totalUses += (uint32_t)header->rtm_use;
            totalPacketsSent += header->rtm_rmx.rmx_pksent;

            bool interfaceSeen = false;
            for (int interfaceIndex = 0; interfaceIndex < interfaceCount; interfaceIndex++) {
                if (interfaceIndices[interfaceIndex] == header->rtm_index) {
                    interfaceSeen = true;
                    break;
                }
            }
            if (!interfaceSeen &&
                interfaceCount < (int)(sizeof(interfaceIndices) / sizeof(interfaceIndices[0]))) {
                interfaceIndices[interfaceCount++] = header->rtm_index;
            }
            next += header->rtm_msglen;
        }
        TEPAppend(
            buffer,
            "route.%s.summary entries=%d interfaces=%d up=%d gateway=%d host=%d llinfo=%d dynamic=%d modified=%d static=%d blackhole=%d reject=%d local=%d broadcast=%d multicast=%d ifscope=%d proxy=%d router=%d global=%d expiring=%d with_mtu=%d with_rtt=%d with_packets_sent=%d total_uses=%llu total_packets_sent=%llu\n",
            label,
            entries,
            interfaceCount,
            up,
            gateway,
            host,
            llinfo,
            dynamic,
            modified,
            routeStatic,
            blackhole,
            reject,
            local,
            broadcast,
            multicast,
            ifscope,
            proxy,
            router,
            global,
            expiring,
            mtu,
            rtt,
            packetsSent,
            (unsigned long long)totalUses,
            (unsigned long long)totalPacketsSent
        );
    }
    free(raw);
}

#if TARGET_OS_OSX

static void TEPAppendPcbListNSummary(
    TEPBuffer *buffer,
    const char *name,
    const void *raw,
    size_t length
) {
    if (length < 24) {
        return;
    }

    uint32_t headerLength = 0;
    uint32_t declaredCount = 0;
    memcpy(&headerLength, raw, sizeof(headerLength));
    memcpy(&declaredCount, (const char *)raw + sizeof(headerLength), sizeof(declaredCount));
    if (headerLength < 8 || headerLength > length) {
        return;
    }

    enum {
        TEP_XSO_SOCKET = 0x001,
        TEP_XSO_RCVBUF = 0x002,
        TEP_XSO_SNDBUF = 0x004,
        TEP_XSO_STATS = 0x008,
        TEP_XSO_INPCB = 0x010,
        TEP_XSO_TCPCB = 0x020,
    };

    size_t offset = headerLength;
    int inpcbCount = 0;
    int socketCount = 0;
    int receiveBufferCount = 0;
    int sendBufferCount = 0;
    int statsCount = 0;
    int tcpcbCount = 0;
    int localPortCount = 0;
    int foreignPortCount = 0;
    int ipv4Count = 0;
    int ipv6Count = 0;
    int tcpStates[16] = {0};
    pid_t pids[1024] = {0};
    int pidCount = 0;
    bool completeFooter = false;

    while (offset + 8 <= length) {
        uint32_t componentLength = 0;
        uint32_t componentKind = 0;
        memcpy(&componentLength, (const char *)raw + offset, sizeof(componentLength));
        memcpy(
            &componentKind,
            (const char *)raw + offset + sizeof(componentLength),
            sizeof(componentKind)
        );

        if (componentLength == headerLength && offset + componentLength == length) {
            completeFooter = true;
            break;
        }
        if (componentLength < 8 || offset + componentLength > length) {
            break;
        }

        if (componentKind == TEP_XSO_INPCB) {
            inpcbCount++;
            if (componentLength >= 48) {
                uint16_t foreignPort = 0;
                uint16_t localPort = 0;
                uint8_t versionFlags = 0;
                memcpy(&foreignPort, (const char *)raw + offset + 16, sizeof(foreignPort));
                memcpy(&localPort, (const char *)raw + offset + 18, sizeof(localPort));
                memcpy(&versionFlags, (const char *)raw + offset + 44, sizeof(versionFlags));
                foreignPortCount += foreignPort != 0;
                localPortCount += localPort != 0;
                ipv4Count += (versionFlags & 0x1) != 0;
                ipv6Count += (versionFlags & 0x2) != 0;
            }
        } else if (componentKind == TEP_XSO_SOCKET) {
            socketCount++;
            if (componentLength >= 76) {
                pid_t candidatePIDs[2] = {0};
                memcpy(&candidatePIDs[0], (const char *)raw + offset + 68, sizeof(pid_t));
                memcpy(&candidatePIDs[1], (const char *)raw + offset + 72, sizeof(pid_t));
                for (size_t candidate = 0; candidate < 2; candidate++) {
                    pid_t pid = candidatePIDs[candidate];
                    if (pid <= 0) {
                        continue;
                    }
                    bool alreadyPresent = false;
                    for (int index = 0; index < pidCount; index++) {
                        if (pids[index] == pid) {
                            alreadyPresent = true;
                            break;
                        }
                    }
                    if (!alreadyPresent && pidCount < (int)(sizeof(pids) / sizeof(pids[0]))) {
                        pids[pidCount++] = pid;
                    }
                }
            }
        } else if (componentKind == TEP_XSO_RCVBUF) {
            receiveBufferCount++;
        } else if (componentKind == TEP_XSO_SNDBUF) {
            sendBufferCount++;
        } else if (componentKind == TEP_XSO_STATS) {
            statsCount++;
        } else if (componentKind == TEP_XSO_TCPCB) {
            tcpcbCount++;
            if (componentLength >= 40) {
                int32_t state = 0;
                memcpy(&state, (const char *)raw + offset + 36, sizeof(state));
                if (state >= 0 && state < (int)(sizeof(tcpStates) / sizeof(tcpStates[0]))) {
                    tcpStates[state]++;
                }
            }
        }

        offset += (componentLength + 7u) & ~7u;
    }

    int foreignPIDCount = 0;
    int namedPIDCount = 0;
    int pathPIDCount = 0;
    int bsdInfoPIDCount = 0;
    int resourceUsagePIDCount = 0;
    pid_t selfPID = getpid();
    for (int index = 0; index < pidCount; index++) {
        foreignPIDCount += pids[index] != selfPID;
        char processName[PROC_PIDPATHINFO_MAXSIZE] = {0};
        namedPIDCount += proc_name(pids[index], processName, sizeof(processName)) > 0;
        char processPath[PROC_PIDPATHINFO_MAXSIZE] = {0};
        pathPIDCount += proc_pidpath(pids[index], processPath, sizeof(processPath)) > 0;

        struct proc_bsdinfo bsdInfo = {0};
        bsdInfoPIDCount += proc_pidinfo(
            pids[index],
            PROC_PIDTBSDINFO,
            0,
            &bsdInfo,
            sizeof(bsdInfo)
        ) == (int)sizeof(bsdInfo);

        struct rusage_info_v0 resourceUsage = {0};
        resourceUsagePIDCount += proc_pid_rusage(
            pids[index],
            RUSAGE_INFO_V0,
            (rusage_info_t *)&resourceUsage
        ) == 0;
    }

    TEPAppend(
        buffer,
        "sysctl.%s.summary declared=%u inpcb=%d sockets=%d recv_buffers=%d send_buffers=%d stats=%d tcpcb=%d local_ports=%d foreign_ports=%d ipv4=%d ipv6=%d unique_pids=%d foreign_pids=%d named_pids=%d path_pids=%d bsd_info_pids=%d resource_usage_pids=%d complete_footer=%s\n",
        name,
        declaredCount,
        inpcbCount,
        socketCount,
        receiveBufferCount,
        sendBufferCount,
        statsCount,
        tcpcbCount,
        localPortCount,
        foreignPortCount,
        ipv4Count,
        ipv6Count,
        pidCount,
        foreignPIDCount,
        namedPIDCount,
        pathPIDCount,
        bsdInfoPIDCount,
        resourceUsagePIDCount,
        completeFooter ? "true" : "false"
    );
    for (int state = 0; state < (int)(sizeof(tcpStates) / sizeof(tcpStates[0])); state++) {
        if (tcpStates[state] > 0) {
            TEPAppend(
                buffer,
                "sysctl.%s.tcp_state value=%d count=%d\n",
                name,
                state,
                tcpStates[state]
            );
        }
    }
}

#endif

static void TEPReadNamedSysctl(TEPBuffer *buffer, const char *name) {
    size_t needed = 0;
    errno = 0;
    int sizeResult = sysctlbyname(name, NULL, &needed, NULL, 0);
    int sizeError = errno;
    TEPAppend(
        buffer,
        "sysctl.%s.size result=%d errno=%d message=%s bytes=%zu\n",
        name,
        sizeResult,
        sizeError,
        sizeError == 0 ? "none" : strerror(sizeError),
        needed
    );
    if (sizeResult != 0 || needed == 0 || needed > (64u * 1024u * 1024u)) {
        return;
    }

    void *raw = malloc(needed);
    if (raw == NULL) {
        TEPAppend(buffer, "sysctl.%s.read=error reason=allocation bytes=%zu\n", name, needed);
        return;
    }

    errno = 0;
    int readResult = sysctlbyname(name, raw, &needed, NULL, 0);
    int readError = errno;
    TEPAppend(
        buffer,
        "sysctl.%s.read result=%d errno=%d message=%s bytes=%zu\n",
        name,
        readResult,
        readError,
        readError == 0 ? "none" : strerror(readError),
        needed
    );
    if (readResult == 0 && needed >= 8 && strstr(name, "_n") == NULL) {
        uint32_t headerLength = 0;
        uint32_t declaredCount = 0;
        memcpy(&headerLength, raw, sizeof(headerLength));
        memcpy(&declaredCount, (const char *)raw + sizeof(headerLength), sizeof(declaredCount));

        size_t visibleCount = 0;
        size_t offset = headerLength;
        bool completeFooter = false;
        while (headerLength >= 8 && offset + sizeof(uint32_t) <= needed) {
            uint32_t recordLength = 0;
            memcpy(&recordLength, (const char *)raw + offset, sizeof(recordLength));
            if (recordLength == 0 || offset + recordLength > needed) {
                break;
            }
            if (recordLength == headerLength && offset + recordLength == needed) {
                completeFooter = true;
                break;
            }
            visibleCount++;
            offset += recordLength;
        }

        TEPAppend(
            buffer,
            "sysctl.%s.summary declared=%u visible=%zu header_len=%u complete_footer=%s\n",
            name,
            declaredCount,
            visibleCount,
            headerLength,
        completeFooter ? "true" : "false"
        );
    }
#if TARGET_OS_OSX
    if (readResult == 0 && needed >= 8 && strstr(name, "_n") != NULL) {
        TEPAppendPcbListNSummary(buffer, name, raw, needed);
    }
#endif
    free(raw);
}

static void TEPProbeSpecialSockets(TEPBuffer *buffer) {
    errno = 0;
    int routeSocket = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    int routeError = errno;
    TEPAppend(
        buffer,
        "socket.route result=%d errno=%d message=%s\n",
        routeSocket,
        routeError,
        routeError == 0 ? "none" : strerror(routeError)
    );
    if (routeSocket >= 0) {
        close(routeSocket);
    }

#if __has_include(<sys/kern_event.h>)
    errno = 0;
    int eventSocket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_EVENT);
    int eventError = errno;
    TEPAppend(
        buffer,
        "socket.kernel_event result=%d errno=%d message=%s\n",
        eventSocket,
        eventError,
        eventError == 0 ? "none" : strerror(eventError)
    );
    if (eventSocket >= 0) {
        close(eventSocket);
    }
#else
    TEPAppend(
        buffer,
        "socket.kernel_event=unsupported reason=headers-not-in-public-device-sdk\n"
    );
#endif
}

static int TEPConnectNamedKernelControl(
    TEPBuffer *buffer,
    const char *label,
    const char *name
) {
    errno = 0;
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    int socketError = errno;
    TEPAppend(
        buffer,
        "kernel_control.%s.socket result=%d errno=%d message=%s\n",
        label,
        fd,
        socketError,
        socketError == 0 ? "none" : strerror(socketError)
    );
    if (fd < 0) {
        return -1;
    }

    TEPControlInfo info = {0};
    strlcpy(info.ctl_name, name, sizeof(info.ctl_name));
    errno = 0;
    int lookupResult = ioctl(fd, TEP_CTLIOCGINFO, &info);
    int lookupError = errno;
    TEPAppend(
        buffer,
        "kernel_control.%s.lookup result=%d errno=%d message=%s id=%u\n",
        label,
        lookupResult,
        lookupError,
        lookupError == 0 ? "none" : strerror(lookupError),
        info.ctl_id
    );
    if (lookupResult != 0) {
        close(fd);
        return -1;
    }

    TEPSockaddrControl address = {
        .sc_len = sizeof(address),
        .sc_family = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_id = info.ctl_id,
        .sc_unit = 0,
    };
    errno = 0;
    int connectResult = connect(
        fd,
        (const struct sockaddr *)&address,
        sizeof(address)
    );
    int connectError = errno;
    TEPAppend(
        buffer,
        "kernel_control.%s.connect result=%d errno=%d message=%s\n",
        label,
        connectResult,
        connectError,
        connectError == 0 ? "none" : strerror(connectError)
    );
    if (connectResult != 0) {
        close(fd);
        return -1;
    }

    int receiveBuffer = 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receiveBuffer, sizeof(receiveBuffer));
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return fd;
}

static void TEPProbeControlConnectOnly(
    TEPBuffer *buffer,
    const char *label,
    const char *name
) {
    int fd = TEPConnectNamedKernelControl(buffer, label, name);
    if (fd >= 0) {
        close(fd);
    }
}

static void TEPNstatAddPID(TEPNstatSummary *summary, uint64_t pid) {
    if (pid == 0) {
        return;
    }
    for (int index = 0; index < summary->sourcePIDCount; index++) {
        if (summary->sourcePIDs[index] == pid) {
            return;
        }
    }
    if (summary->sourcePIDCount <
        (int)(sizeof(summary->sourcePIDs) / sizeof(summary->sourcePIDs[0]))) {
        summary->sourcePIDs[summary->sourcePIDCount++] = pid;
    }
}

static void TEPNstatAccumulateCounts(
    TEPNstatSummary *summary,
    const TEPNstatCounts *counts
) {
    summary->rxPackets += counts->rxPackets;
    summary->rxBytes += counts->rxBytes;
    summary->txPackets += counts->txPackets;
    summary->txBytes += counts->txBytes;
    summary->wifiRxBytes += counts->wifiRxBytes;
    summary->wifiTxBytes += counts->wifiTxBytes;
    summary->wiredRxBytes += counts->wiredRxBytes;
    summary->wiredTxBytes += counts->wiredTxBytes;
    summary->cellularRxBytes += counts->cellularRxBytes;
    summary->cellularTxBytes += counts->cellularTxBytes;
    summary->connectionAttempts += counts->connectionAttempts;
    summary->connectionSuccesses += counts->connectionSuccesses;
}

static void TEPNstatParseMessage(
    TEPNstatSummary *summary,
    const unsigned char *message,
    size_t length
) {
    if (length < sizeof(TEPNstatMessageHeader)) {
        summary->malformed++;
        return;
    }

    const TEPNstatMessageHeader *header =
        (const TEPNstatMessageHeader *)message;
    summary->messages++;
    summary->continuation += (header->flags & (1u << 1)) != 0;

    switch (header->type) {
        case TEP_NSTAT_MSG_SUCCESS:
            summary->success++;
            break;
        case TEP_NSTAT_MSG_ERROR:
            summary->errors++;
            if (length >= sizeof(TEPNstatMessageHeader) + sizeof(uint32_t)) {
                uint32_t error = 0;
                memcpy(
                    &error,
                    message + sizeof(TEPNstatMessageHeader),
                    sizeof(error)
                );
                if (summary->firstError == 0) {
                    summary->firstError = (int)error;
                }
            }
            break;
        case TEP_NSTAT_MSG_SRC_ADDED:
            summary->sourceAdded++;
            break;
        case TEP_NSTAT_MSG_SRC_REMOVED:
            summary->sourceRemoved++;
            break;
        case TEP_NSTAT_MSG_SRC_DESC:
            summary->descriptions++;
            break;
        case TEP_NSTAT_MSG_SRC_COUNTS:
            summary->counts++;
            if (length >=
                sizeof(TEPNstatMessageHeader) +
                sizeof(uint64_t) +
                sizeof(uint64_t) +
                sizeof(TEPNstatCounts)) {
                const TEPNstatCounts *counts = (const TEPNstatCounts *)(
                    message +
                    sizeof(TEPNstatMessageHeader) +
                    sizeof(uint64_t) +
                    sizeof(uint64_t)
                );
                TEPNstatAccumulateCounts(summary, counts);
            }
            break;
        case TEP_NSTAT_MSG_SRC_UPDATE:
        case TEP_NSTAT_MSG_SRC_EXTENDED_UPDATE: {
            if (header->type == TEP_NSTAT_MSG_SRC_UPDATE) {
                summary->updates++;
            } else {
                summary->extendedUpdates++;
            }
            if (length < sizeof(TEPNstatUpdatePrefix)) {
                summary->malformed++;
                break;
            }

            const TEPNstatUpdatePrefix *update =
                (const TEPNstatUpdatePrefix *)message;
            TEPNstatAccumulateCounts(summary, &update->counts);

            const unsigned char *descriptor =
                message + sizeof(TEPNstatUpdatePrefix);
            size_t descriptorLength =
                length - sizeof(TEPNstatUpdatePrefix);
            if ((update->provider == TEP_NSTAT_PROVIDER_TCP_KERNEL ||
                update->provider == TEP_NSTAT_PROVIDER_TCP_USERLAND ||
                update->provider == TEP_NSTAT_PROVIDER_QUIC_USERLAND) &&
                descriptorLength >= sizeof(TEPNstatTCPDescriptorPrefix)) {
                const TEPNstatTCPDescriptorPrefix *tcp =
                    (const TEPNstatTCPDescriptorPrefix *)descriptor;
                TEPNstatAddPID(summary, tcp->pid);
                TEPNstatAddPID(summary, tcp->effectivePID);
                if (tcp->state <
                    sizeof(summary->tcpStates) / sizeof(summary->tcpStates[0])) {
                    summary->tcpStates[tcp->state]++;
                }
            } else if ((update->provider == TEP_NSTAT_PROVIDER_UDP_KERNEL ||
                update->provider == TEP_NSTAT_PROVIDER_UDP_USERLAND) &&
                descriptorLength >= 132) {
                uint32_t pid = 0;
                memcpy(&pid, descriptor + 128, sizeof(pid));
                TEPNstatAddPID(summary, pid);
            }
            break;
        }
        case TEP_NSTAT_MSG_SRC_DETAILS:
            summary->details++;
            break;
        case TEP_NSTAT_MSG_SRC_EXTENDED_DETAILS:
            summary->extendedDetails++;
            break;
        case TEP_NSTAT_MSG_SYSINFO_COUNTS:
            summary->counts++;
            break;
        default:
            break;
    }
}

static void TEPNstatDrain(
    int fd,
    TEPNstatSummary *summary,
    int initialTimeoutMilliseconds
) {
    unsigned char *raw = malloc(1024 * 1024);
    if (raw == NULL) {
        summary->malformed++;
        return;
    }

    bool receivedAny = false;
    for (int readIndex = 0; readIndex < 2048; readIndex++) {
        struct pollfd descriptor = {
            .fd = fd,
            .events = POLLIN,
        };
        int timeout = receivedAny ? 30 : initialTimeoutMilliseconds;
        int pollResult = poll(&descriptor, 1, timeout);
        if (pollResult <= 0 || (descriptor.revents & POLLIN) == 0) {
            break;
        }

        errno = 0;
        ssize_t received = recv(fd, raw, 1024 * 1024, MSG_DONTWAIT);
        if (received <= 0) {
            if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                summary->firstError == 0) {
                summary->firstError = errno;
            }
            break;
        }

        receivedAny = true;
        summary->datagrams++;
        size_t offset = 0;
        while (offset + sizeof(TEPNstatMessageHeader) <= (size_t)received) {
            const TEPNstatMessageHeader *header =
                (const TEPNstatMessageHeader *)(raw + offset);
            if (header->length < sizeof(*header) ||
                offset + header->length > (size_t)received) {
                summary->malformed++;
                break;
            }
            TEPNstatParseMessage(summary, raw + offset, header->length);
            offset += header->length;
        }
        if (offset != (size_t)received) {
            summary->malformed++;
        }
    }

    free(raw);
}

static const char *TEPNstatProviderName(uint32_t provider) {
    switch (provider) {
        case TEP_NSTAT_PROVIDER_ROUTE: return "route";
        case TEP_NSTAT_PROVIDER_TCP_KERNEL: return "tcp_kernel";
        case TEP_NSTAT_PROVIDER_TCP_USERLAND: return "tcp_userland";
        case TEP_NSTAT_PROVIDER_UDP_KERNEL: return "udp_kernel";
        case TEP_NSTAT_PROVIDER_UDP_USERLAND: return "udp_userland";
        case TEP_NSTAT_PROVIDER_IFNET: return "ifnet";
        case TEP_NSTAT_PROVIDER_QUIC_USERLAND: return "quic_userland";
        case TEP_NSTAT_PROVIDER_CONN_USERLAND: return "connection_userland";
        case TEP_NSTAT_PROVIDER_UDP_SUBFLOW: return "udp_subflow";
        default: return "unknown";
    }
}

static void TEPProbeNetworkStatisticsProvider(
    TEPBuffer *buffer,
    uint32_t provider
) {
    const char *providerName = TEPNstatProviderName(provider);
    int fd = TEPConnectNamedKernelControl(
        buffer,
        providerName,
        "com.apple.network.statistics"
    );
    if (fd < 0) {
        TEPAppend(
            buffer,
            "nstat.%s.summary status=control-unavailable\n",
            providerName
        );
        return;
    }

    TEPNstatSummary summary = {0};
    TEPNstatAddAllSources add = {
        .header = {
            .context = 0x5445500000000000ull | provider,
            .type = TEP_NSTAT_MSG_ADD_ALL_SRCS,
            .length = sizeof(add),
            .flags = 1,
        },
        .provider = provider,
    };

    errno = 0;
    ssize_t addResult = send(fd, &add, sizeof(add), 0);
    int addError = errno;
    TEPAppend(
        buffer,
        "nstat.%s.add_all result=%zd errno=%d message=%s\n",
        providerName,
        addResult,
        addError,
        addError == 0 ? "none" : strerror(addError)
    );
    if (addResult == sizeof(add)) {
        TEPNstatDrain(fd, &summary, 500);

        TEPNstatQuerySources query = {
            .header = {
                .context = 0x5445510000000000ull | provider,
                .type = TEP_NSTAT_MSG_GET_UPDATE,
                .length = sizeof(query),
                .flags = 1 | (1 << 1),
            },
            .sourceReference = UINT64_MAX,
        };
        for (int fragment = 0; fragment < 16; fragment++) {
            int previousContinuation = summary.continuation;
            errno = 0;
            ssize_t queryResult = send(fd, &query, sizeof(query), 0);
            int queryError = errno;
            if (fragment == 0 || queryResult != sizeof(query)) {
                TEPAppend(
                    buffer,
                    "nstat.%s.get_update fragment=%d result=%zd errno=%d message=%s\n",
                    providerName,
                    fragment,
                    queryResult,
                    queryError,
                    queryError == 0 ? "none" : strerror(queryError)
                );
            }
            if (queryResult != sizeof(query)) {
                break;
            }
            TEPNstatDrain(fd, &summary, 500);
            if (summary.continuation == previousContinuation) {
                break;
            }
        }
    }

    close(fd);
    pid_t selfPID = getpid();
    for (int index = 0; index < summary.sourcePIDCount; index++) {
        summary.foreignPIDCount += summary.sourcePIDs[index] != (uint64_t)selfPID;
    }

    TEPAppend(
        buffer,
        "nstat.%s.summary datagrams=%d messages=%d malformed=%d success=%d errors=%d first_error=%d source_added=%d source_removed=%d descriptions=%d counts=%d updates=%d extended_updates=%d details=%d extended_details=%d continuations=%d unique_pids=%d foreign_pids=%d rx_packets=%llu rx_bytes=%llu tx_packets=%llu tx_bytes=%llu wifi_rx=%llu wifi_tx=%llu wired_rx=%llu wired_tx=%llu cellular_rx=%llu cellular_tx=%llu connection_attempts=%llu connection_successes=%llu\n",
        providerName,
        summary.datagrams,
        summary.messages,
        summary.malformed,
        summary.success,
        summary.errors,
        summary.firstError,
        summary.sourceAdded,
        summary.sourceRemoved,
        summary.descriptions,
        summary.counts,
        summary.updates,
        summary.extendedUpdates,
        summary.details,
        summary.extendedDetails,
        summary.continuation,
        summary.sourcePIDCount,
        summary.foreignPIDCount,
        (unsigned long long)summary.rxPackets,
        (unsigned long long)summary.rxBytes,
        (unsigned long long)summary.txPackets,
        (unsigned long long)summary.txBytes,
        (unsigned long long)summary.wifiRxBytes,
        (unsigned long long)summary.wifiTxBytes,
        (unsigned long long)summary.wiredRxBytes,
        (unsigned long long)summary.wiredTxBytes,
        (unsigned long long)summary.cellularRxBytes,
        (unsigned long long)summary.cellularTxBytes,
        (unsigned long long)summary.connectionAttempts,
        (unsigned long long)summary.connectionSuccesses
    );
    for (int state = 0;
        state < (int)(sizeof(summary.tcpStates) / sizeof(summary.tcpStates[0]));
        state++) {
        if (summary.tcpStates[state] > 0) {
            TEPAppend(
                buffer,
                "nstat.%s.flow_state value=%d count=%d\n",
                providerName,
                state,
                summary.tcpStates[state]
            );
        }
    }
}

static void TEPProbeNetworkStatistics(TEPBuffer *buffer) {
    const uint32_t providers[] = {
        TEP_NSTAT_PROVIDER_ROUTE,
        TEP_NSTAT_PROVIDER_TCP_KERNEL,
        TEP_NSTAT_PROVIDER_TCP_USERLAND,
        TEP_NSTAT_PROVIDER_UDP_KERNEL,
        TEP_NSTAT_PROVIDER_UDP_USERLAND,
        TEP_NSTAT_PROVIDER_IFNET,
        TEP_NSTAT_PROVIDER_QUIC_USERLAND,
        TEP_NSTAT_PROVIDER_CONN_USERLAND,
        TEP_NSTAT_PROVIDER_UDP_SUBFLOW,
    };

    for (size_t index = 0; index < sizeof(providers) / sizeof(providers[0]); index++) {
        TEPProbeNetworkStatisticsProvider(buffer, providers[index]);
    }
}

static TEPTestSockets TEPCreateKnownSockets(TEPBuffer *buffer) {
    TEPTestSockets sockets = {
        .listener = -1,
        .client = -1,
        .accepted = -1,
        .udp = -1,
    };

    sockets.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockets.listener < 0) {
        TEPAppend(buffer, "known_sockets.tcp=error stage=listener errno=%d message=%s\n", errno, strerror(errno));
        return sockets;
    }

    int reuse = 1;
    setsockopt(sockets.listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(sockets.listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(sockets.listener, 1) != 0) {
        TEPAppend(buffer, "known_sockets.tcp=error stage=bind_or_listen errno=%d message=%s\n", errno, strerror(errno));
        return sockets;
    }

    socklen_t addressLength = sizeof(address);
    if (getsockname(sockets.listener, (struct sockaddr *)&address, &addressLength) != 0) {
        TEPAppend(buffer, "known_sockets.tcp=error stage=getsockname errno=%d message=%s\n", errno, strerror(errno));
        return sockets;
    }

    sockets.client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockets.client < 0 ||
        connect(sockets.client, (struct sockaddr *)&address, sizeof(address)) != 0) {
        TEPAppend(buffer, "known_sockets.tcp=error stage=connect errno=%d message=%s\n", errno, strerror(errno));
        return sockets;
    }

    sockets.accepted = accept(sockets.listener, NULL, NULL);
    if (sockets.accepted < 0) {
        TEPAppend(buffer, "known_sockets.tcp=error stage=accept errno=%d message=%s\n", errno, strerror(errno));
        return sockets;
    }

    sockets.udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockets.udp >= 0) {
        connect(sockets.udp, (struct sockaddr *)&address, sizeof(address));
    }

    TEPAppend(
        buffer,
        "known_sockets.created listener=%d client=%d accepted=%d udp=%d port=%u\n",
        sockets.listener,
        sockets.client,
        sockets.accepted,
        sockets.udp,
        ntohs(address.sin_port)
    );
    return sockets;
}

static void TEPCloseKnownSockets(TEPTestSockets sockets) {
    int values[] = {sockets.listener, sockets.client, sockets.accepted, sockets.udp};
    for (size_t index = 0; index < sizeof(values) / sizeof(values[0]); index++) {
        if (values[index] >= 0) {
            close(values[index]);
        }
    }
}

#if TARGET_OS_OSX

static const char *TEPTCPStateName(int state) {
    switch (state) {
        case TSI_S_CLOSED: return "CLOSED";
        case TSI_S_LISTEN: return "LISTEN";
        case TSI_S_SYN_SENT: return "SYN_SENT";
        case TSI_S_SYN_RECEIVED: return "SYN_RECEIVED";
        case TSI_S_ESTABLISHED: return "ESTABLISHED";
        case TSI_S__CLOSE_WAIT: return "CLOSE_WAIT";
        case TSI_S_FIN_WAIT_1: return "FIN_WAIT_1";
        case TSI_S_CLOSING: return "CLOSING";
        case TSI_S_LAST_ACK: return "LAST_ACK";
        case TSI_S_FIN_WAIT_2: return "FIN_WAIT_2";
        case TSI_S_TIME_WAIT: return "TIME_WAIT";
        case TSI_S_RESERVED: return "RESERVED";
        default: return "UNKNOWN";
    }
}

static void TEPFormatEndpoint(
    const struct in_sockinfo *info,
    bool local,
    char *output,
    size_t outputSize
) {
    const void *rawAddress = NULL;
    int family = AF_UNSPEC;
    int port = local ? info->insi_lport : info->insi_fport;
    char addressText[INET6_ADDRSTRLEN] = {0};

    if ((info->insi_vflag & INI_IPV4) != 0) {
        family = AF_INET;
        rawAddress = local
            ? (const void *)&info->insi_laddr.ina_46.i46a_addr4
            : (const void *)&info->insi_faddr.ina_46.i46a_addr4;
    } else if ((info->insi_vflag & INI_IPV6) != 0) {
        family = AF_INET6;
        rawAddress = local
            ? (const void *)&info->insi_laddr.ina_6
            : (const void *)&info->insi_faddr.ina_6;
    }

    if (rawAddress != NULL) {
        inet_ntop(family, rawAddress, addressText, sizeof(addressText));
    }
    snprintf(
        output,
        outputSize,
        "%s:%u",
        addressText[0] == '\0' ? "unknown" : addressText,
        ntohs((uint16_t)port)
    );
}

static void TEPProbeProcessSockets(TEPBuffer *buffer) {
    const int maxPIDs = 4096;
    pid_t *pids = calloc((size_t)maxPIDs, sizeof(pid_t));
    if (pids == NULL) {
        TEPAppend(buffer, "libproc.list=error reason=allocation\n");
        return;
    }

    errno = 0;
    int pidCount = proc_listallpids(pids, maxPIDs * (int)sizeof(pid_t));
    int listError = errno;
    TEPAppend(
        buffer,
        "libproc.list result=%d errno=%d message=%s\n",
        pidCount,
        listError,
        listError == 0 ? "none" : strerror(listError)
    );
    if (pidCount <= 0) {
        free(pids);
        return;
    }

    int accessibleProcesses = 0;
    int deniedProcesses = 0;
    int vanishedProcesses = 0;
    int otherProcessErrors = 0;
    int socketInfoSuccess = 0;
    int socketInfoDenied = 0;
    int socketInfoOtherError = 0;
    int selfSocketSuccess = 0;
    int foreignSocketSuccess = 0;
    int tcpStates[TSI_S_RESERVED + 1] = {0};
    int sampleCount = 0;
    pid_t selfPID = getpid();

    struct proc_fdinfo fdInfos[1024];
    for (int pidIndex = 0; pidIndex < pidCount && pidIndex < maxPIDs; pidIndex++) {
        pid_t pid = pids[pidIndex];
        if (pid <= 0) {
            continue;
        }

        errno = 0;
        int fdBytes = proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            fdInfos,
            (int)sizeof(fdInfos)
        );
        int fdError = errno;
        if (fdBytes <= 0) {
            if (fdError == EPERM || fdError == EACCES) {
                deniedProcesses++;
            } else if (fdError == ESRCH) {
                vanishedProcesses++;
            } else {
                otherProcessErrors++;
            }
            continue;
        }

        accessibleProcesses++;
        int fdCount = fdBytes / (int)sizeof(struct proc_fdinfo);
        for (int fdIndex = 0; fdIndex < fdCount; fdIndex++) {
            if (fdInfos[fdIndex].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            struct socket_fdinfo socketInfo = {0};
            errno = 0;
            int infoBytes = proc_pidfdinfo(
                pid,
                fdInfos[fdIndex].proc_fd,
                PROC_PIDFDSOCKETINFO,
                &socketInfo,
                (int)sizeof(socketInfo)
            );
            int infoError = errno;
            if (infoBytes != (int)sizeof(socketInfo)) {
                if (infoError == EPERM || infoError == EACCES) {
                    socketInfoDenied++;
                } else {
                    socketInfoOtherError++;
                }
                continue;
            }

            socketInfoSuccess++;
            if (pid == selfPID) {
                selfSocketSuccess++;
            } else {
                foreignSocketSuccess++;
            }

            if (socketInfo.psi.soi_kind == SOCKINFO_TCP) {
                int state = socketInfo.psi.soi_proto.pri_tcp.tcpsi_state;
                if (state >= 0 && state <= TSI_S_RESERVED) {
                    tcpStates[state]++;
                }

                if (pid != selfPID && sampleCount < 24) {
                    char processName[PROC_PIDPATHINFO_MAXSIZE] = {0};
                    char local[INET6_ADDRSTRLEN + 16] = {0};
                    char remote[INET6_ADDRSTRLEN + 16] = {0};
                    proc_name(pid, processName, sizeof(processName));
                    TEPFormatEndpoint(
                        &socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini,
                        true,
                        local,
                        sizeof(local)
                    );
                    TEPFormatEndpoint(
                        &socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini,
                        false,
                        remote,
                        sizeof(remote)
                    );
                    TEPAppend(
                        buffer,
                        "libproc.foreign_tcp process=%s pid=%d fd=%d state=%s local=%s remote=%s\n",
                        processName[0] == '\0' ? "unknown" : processName,
                        pid,
                        fdInfos[fdIndex].proc_fd,
                        TEPTCPStateName(state),
                        local,
                        remote
                    );
                    sampleCount++;
                }
            }
        }
    }

    free(pids);
    TEPAppend(
        buffer,
        "libproc.summary pids=%d accessible_processes=%d denied_processes=%d vanished_processes=%d other_process_errors=%d socket_success=%d self_socket_success=%d foreign_socket_success=%d socket_denied=%d socket_other_error=%d\n",
        pidCount,
        accessibleProcesses,
        deniedProcesses,
        vanishedProcesses,
        otherProcessErrors,
        socketInfoSuccess,
        selfSocketSuccess,
        foreignSocketSuccess,
        socketInfoDenied,
        socketInfoOtherError
    );
    for (int state = 0; state <= TSI_S_RESERVED; state++) {
        if (tcpStates[state] > 0) {
            TEPAppend(
                buffer,
                "libproc.tcp_state state=%s value=%d count=%d\n",
                TEPTCPStateName(state),
                state,
                tcpStates[state]
            );
        }
    }
}

#else

static void TEPProbeProcessSockets(TEPBuffer *buffer) {
    TEPAppend(
        buffer,
        "libproc.unsupported platform=iOS/iPadOS reason=headers-not-in-public-device-sdk\n"
    );
}

#endif

const char *TEPCopyProbeReport(void) {
    TEPBuffer buffer = {0};
    TEPAppend(&buffer, "probe.c.begin\n");
    TEPAppend(
        &buffer,
        "process pid=%d uid=%d euid=%d\n",
        getpid(),
        getuid(),
        geteuid()
    );

    TEPIPv4Selection selection = TEPAppendInterfaces(&buffer);
    TEPProbeSpecialSockets(&buffer);
    TEPProbeControlConnectOnly(
        &buffer,
        "necp",
        "com.apple.net.necp_control"
    );
    TEPProbeControlConnectOnly(
        &buffer,
        "netagent",
        "com.apple.net.netagent"
    );
    TEPTestSockets testSockets = TEPCreateKnownSockets(&buffer);
    TEPReadRouteOperation(&buffer, "dump_ipv4", AF_INET, NET_RT_DUMP, 0);
    TEPReadRouteOperation(&buffer, "dump2_ipv4", AF_INET, NET_RT_DUMP2, 0);
    TEPReadRouteOperation(&buffer, "dump_ipv6", AF_INET6, NET_RT_DUMP, 0);
    TEPReadRouteOperation(&buffer, "dump2_ipv6", AF_INET6, NET_RT_DUMP2, 0);
    TEPReadRouteOperation(&buffer, "iflist2", AF_UNSPEC, NET_RT_IFLIST2, 0);
#if defined(NET_RT_IFLIST)
    TEPReadRouteOperation(&buffer, "iflist", AF_UNSPEC, NET_RT_IFLIST, 0);
#endif
#if defined(NET_RT_STAT)
    TEPReadRouteOperation(&buffer, "statistics", AF_UNSPEC, NET_RT_STAT, 0);
#endif
#if defined(NET_RT_TRASH)
    TEPReadRouteOperation(&buffer, "trash", AF_UNSPEC, NET_RT_TRASH, 0);
#endif
    TEPRouteEventCapture routeEvents = TEPBeginRouteEventCapture(&buffer);
    TEPWarmNeighborCache(&buffer, selection);
    TEPEndRouteEventCapture(&buffer, routeEvents);
    TEPReadNeighbors(&buffer, "ipv4.standard", AF_INET, NET_RT_FLAGS);
    TEPReadNeighbors(&buffer, "ipv6.standard", AF_INET6, NET_RT_FLAGS);
#if defined(NET_RT_FLAGS_PRIV)
    TEPReadNeighbors(&buffer, "ipv4.privileged", AF_INET, NET_RT_FLAGS_PRIV);
    TEPReadNeighbors(&buffer, "ipv6.privileged", AF_INET6, NET_RT_FLAGS_PRIV);
#else
    TEPAppend(&buffer, "neighbors.privileged=unsupported reason=NET_RT_FLAGS_PRIV-not-defined\n");
#endif

    const char *sysctls[] = {
        "net.inet.tcp.pcblist_n",
        "net.inet.tcp.pcblist",
        "net.inet.udp.pcblist_n",
        "net.inet.udp.pcblist",
        "net.inet.raw.pcblist",
    };
    for (size_t index = 0; index < sizeof(sysctls) / sizeof(sysctls[0]); index++) {
        TEPReadNamedSysctl(&buffer, sysctls[index]);
    }

    TEPProbeNetworkStatistics(&buffer);
    TEPProbeProcessSockets(&buffer);
    TEPCloseKnownSockets(testSockets);

    TEPAppend(&buffer, "probe.c.end\n");
    if (buffer.data == NULL) {
        return strdup("probe.c.error=buffer-allocation\n");
    }
    return buffer.data;
}

void TEPFreeProbeReport(const char *report) {
    free((void *)report);
}
