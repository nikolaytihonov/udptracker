#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define INIT_CONNECTION_ID  0x41727101980ULL
#define ACTION_CONNECT      0
#define ACTION_ANNOUNCE     1
#define ANNOUNCE_NUMWANT    -1

struct connect_request_s {
    uint64_t connection_id;
    uint32_t action;
    uint32_t transaction_id;
} __attribute__((packed));

struct connect_response_s {
    uint32_t action;
    uint32_t transaction_id;
    uint64_t connection_id;
} __attribute__((packed));

struct announce_request_s {
    uint64_t connection_id;
    uint32_t action;
    uint32_t transaction_id;
    uint8_t info_hash[20];
    uint8_t peer_id[20];
    uint64_t downloaded;
    uint64_t left;
    uint64_t uploaded;
    uint32_t event;
    uint32_t ip_address;
    uint32_t key;
    int32_t numwant;
    uint16_t port;
} __attribute__((packed));

struct peer_s {
    uint32_t ip_address;
    uint16_t port;
} __attribute__((packed));

struct announce_response_s {
    uint32_t action;
    uint32_t transaction_id;
    uint32_t interval;
    uint32_t leechers;
    uint32_t seeders;
    struct peer_s peers[1];
} __attribute__((packed));

static void _sendto(int sockfd, const void* data, size_t size,
    const struct sockaddr* paddr, socklen_t socklen)
{
    ssize_t sent = sendto(sockfd, data, size, 0, paddr, socklen);
    if (sent == -1)
    {
        fprintf(stderr, "sendto errno %d error %s\n",
            errno, strerror(errno));
    }
}

static ssize_t _recvfrom(int sockfd, void* data, size_t size,
    struct sockaddr* paddr, socklen_t* socklen)
{
    ssize_t read = recvfrom(sockfd, data, size, 0, paddr, socklen);
    if (read == -1)
    {
        fprintf(stderr, "recvfrom errno %d error %s\n",
            errno, strerror(errno));
    }

    return read;
}

int htoi(char h)
{
    return h < 0x3A ? h - 0x30 : h - 0x57; 
}

void strhex(const char* str, uint8_t* out)
{
    for (unsigned i = 0; i < strlen(str) >> 1; i++)
        out[i] = htoi(str[i<<1]) << 4 | htoi(str[i<<1|1]);
}

int main(int argc, char** argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "%s <host> <port> <hash>\n", argv[0]);
        return 1;
    }

    struct hostent* host = gethostbyname(argv[1]);
    if (!host)
    {
        fprintf(stderr, "Host not found: %d\n", errno);
        return 1;
    }

    if (host->h_addrtype == AF_INET6)
    {
        char buf[48] = {0};
        fprintf(stderr, "IPv6 not supported yet: %s\n",
            inet_ntop(AF_INET6, host->h_addr_list[0], buf, 48));
        return 1;
    }

    struct sockaddr_in addr = {0};
    struct sockaddr* paddr = (struct sockaddr*)&addr;
    socklen_t addrlen = sizeof(addr);
    addr.sin_family = host->h_addrtype;
    memcpy(&addr.sin_addr, host->h_addr_list[0], addrlen);
    addr.sin_port = htons(atoi(argv[2]));

    printf("%s\t%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    srand(time(NULL));
    uint64_t connection_id = INIT_CONNECTION_ID;
    {
        uint32_t transaction_id = rand();
        printf("connect\ttransaction\t%u\n", transaction_id);

        struct connect_request_s req = {
            .connection_id = __bswap_64(INIT_CONNECTION_ID),
            .action = __bswap_32(ACTION_CONNECT),
            .transaction_id = transaction_id
        };
        _sendto(sockfd, &req, sizeof(req), paddr, addrlen);

        struct connect_response_s res = {0};
        _recvfrom(sockfd, &res, sizeof(res), paddr, &addrlen);
        res.action = __bswap_32(res.action);
        res.transaction_id = __bswap_32(res.transaction_id);
        res.connection_id = __bswap_64(res.connection_id);
        printf("%u\t%u\t%lu\n", res.action,
            res.transaction_id, res.connection_id);

        connection_id = res.connection_id;
    }

    {
        uint32_t transaction_id = rand();
        printf("announce\ttransaction\t%u\n", transaction_id);

        struct announce_request_s req = {
            .connection_id = __bswap_64(connection_id),
            .action = __bswap_32(ACTION_ANNOUNCE),
            .transaction_id = __bswap_32(transaction_id),
            .downloaded = __bswap_64(0),
            .left = __bswap_64(0),
            .uploaded = __bswap_64(0),
            .event = __bswap_32(0),
            .ip_address = INADDR_LOOPBACK,
            .key = __bswap_32(0),
            .numwant = __bswap_32(ANNOUNCE_NUMWANT),
            .port = htons(10126)
        };
        for (unsigned i = 0; i < 20; i++)
            req.peer_id[i] = rand() & 0xFF;
        strhex(argv[3], req.info_hash);
        _sendto(sockfd, &req, sizeof(req), paddr, addrlen);

        uint8_t* packet = (uint8_t*)malloc(65536);
        struct announce_response_s* res = (struct announce_response_s*)packet;
        _recvfrom(sockfd, res, 65536, paddr, &addrlen);
        res->action = __bswap_32(res->action);
        res->transaction_id = __bswap_32(res->transaction_id);
        res->interval = __bswap_32(res->interval);
        res->leechers = __bswap_32(res->leechers);
        res->seeders = __bswap_32(res->seeders);
        printf("%u\t%u\t%u\t%u\t%u\n", res->action, res->transaction_id,
            res->interval, res->leechers, res->seeders);
        
        unsigned count = res->leechers + res->seeders;
        for (unsigned i = 0; i < count; i++)
        {
            struct peer_s* peer = &res->peers[i];
            struct in_addr addr = {.s_addr = peer->ip_address};
            unsigned port = ntohs(peer->port);
            printf("%s\t%d\n", inet_ntoa(addr), port);
        }

        free(packet);
    }

    close(sockfd);

    return 0;
}