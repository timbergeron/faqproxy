#ifndef FAQPROXY_NQ_PROTOCOL_H
#define FAQPROXY_NQ_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NQ_DEFAULT_PORT 26000
#define NQ_NET_PROTOCOL_VERSION 3

#define NQ_NETFLAG_LENGTH_MASK UINT32_C(0x0000ffff)
#define NQ_NETFLAG_DATA UINT32_C(0x00010000)
#define NQ_NETFLAG_ACK UINT32_C(0x00020000)
#define NQ_NETFLAG_NAK UINT32_C(0x00040000)
#define NQ_NETFLAG_EOM UINT32_C(0x00080000)
#define NQ_NETFLAG_UNRELIABLE UINT32_C(0x00100000)
#define NQ_NETFLAG_CTL UINT32_C(0x80000000)

#define NQ_CCREQ_CONNECT 0x01
#define NQ_CCREQ_SERVER_INFO 0x02
#define NQ_CCREQ_PLAYER_INFO 0x03
#define NQ_CCREQ_RULE_INFO 0x04
#define NQ_CCREQ_RCON 0x05

#define NQ_CCREP_ACCEPT 0x81
#define NQ_CCREP_REJECT 0x82

#define NQ_PROTOCOL_NETQUAKE 15
#define NQ_PROTOCOL_FITZQUAKE 666
#define NQ_PROTOCOL_RMQ 999

#define NQ_PRFL_SHORTANGLE (UINT32_C(1) << 1)
#define NQ_PRFL_FLOATANGLE (UINT32_C(1) << 2)

#define NQ_SVC_SERVERINFO 11

typedef struct nq_packet_view {
    uint32_t flags;
    uint32_t sequence;
    size_t payload_offset;
    size_t payload_length;
    bool control;
    uint8_t command;
} nq_packet_view;

uint32_t nq_read_be32(const uint8_t *data);
uint32_t nq_read_le32(const uint8_t *data);
void nq_write_be32(uint8_t *data, uint32_t value);
void nq_write_le32(uint8_t *data, uint32_t value);

bool nq_parse_packet(const uint8_t *data, size_t length, nq_packet_view *view);
bool nq_is_connect_request(const uint8_t *data, size_t length, bool *proquake_requested);

size_t nq_make_reject(uint8_t *output, size_t capacity, const char *reason);
size_t nq_rewrite_accept(uint8_t *output, size_t capacity, const uint8_t *input,
                         size_t input_length, uint16_t proxy_port);
bool nq_accept_port(const uint8_t *data, size_t length, uint16_t *port);

bool nq_supported_protocol(int protocol);
const char *nq_protocol_name(int protocol);
int nq_find_server_protocol(const uint8_t *message, size_t length, uint32_t *protocol_flags);

#endif
