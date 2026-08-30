#include "nq_protocol.h"

#include <string.h>

#define NQ_PROTOCOL_FTE_PEXT1 UINT32_C(0x58455446) /* "FTEX" on the wire */
#define NQ_PROTOCOL_FTE_PEXT2 UINT32_C(0x32455446) /* "FTE2" on the wire */

uint32_t nq_read_be32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

uint32_t nq_read_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

void nq_write_be32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

void nq_write_le32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)(value >> 16);
    data[3] = (uint8_t)(value >> 24);
}

bool nq_parse_packet(const uint8_t *data, size_t length, nq_packet_view *view)
{
    uint32_t header;
    uint32_t encoded_length;
    uint32_t flags;

    if (!data || !view || length < 4)
        return false;

    header = nq_read_be32(data);
    encoded_length = header & NQ_NETFLAG_LENGTH_MASK;
    flags = header & ~NQ_NETFLAG_LENGTH_MASK;
    if (encoded_length != length)
        return false;

    memset(view, 0, sizeof(*view));
    view->flags = flags;
    if (flags == NQ_NETFLAG_CTL) {
        if (length < 5)
            return false;
        view->control = true;
        view->command = data[4];
        view->payload_offset = 5;
        view->payload_length = length - 5;
        return true;
    }

    if (flags & NQ_NETFLAG_CTL)
        return false;
    if (length < 8)
        return false;
    if (!(flags & (NQ_NETFLAG_DATA | NQ_NETFLAG_ACK | NQ_NETFLAG_NAK | NQ_NETFLAG_UNRELIABLE)))
        return false;

    view->sequence = nq_read_be32(data + 4);
    view->payload_offset = 8;
    view->payload_length = length - 8;
    return true;
}

bool nq_is_connect_request(const uint8_t *data, size_t length, bool *proquake_requested)
{
    static const uint8_t game_name[] = {'Q', 'U', 'A', 'K', 'E', 0};
    nq_packet_view view;
    size_t version_offset;

    if (proquake_requested)
        *proquake_requested = false;
    if (!nq_parse_packet(data, length, &view) || !view.control || view.command != NQ_CCREQ_CONNECT)
        return false;

    version_offset = view.payload_offset + sizeof(game_name);
    if (length <= version_offset ||
        memcmp(data + view.payload_offset, game_name, sizeof(game_name)) != 0 ||
        data[version_offset] != NQ_NET_PROTOCOL_VERSION)
        return false;

    if (proquake_requested && length > version_offset + 1)
        *proquake_requested = data[version_offset + 1] == 1;
    return true;
}

size_t nq_make_reject(uint8_t *output, size_t capacity, const char *reason)
{
    size_t reason_length;
    size_t length;

    if (!output || !reason)
        return 0;
    reason_length = strlen(reason) + 1;
    length = 5 + reason_length;
    if (length > capacity || length > NQ_NETFLAG_LENGTH_MASK)
        return 0;

    nq_write_be32(output, NQ_NETFLAG_CTL | (uint32_t)length);
    output[4] = NQ_CCREP_REJECT;
    memcpy(output + 5, reason, reason_length);
    return length;
}

size_t nq_rewrite_accept(uint8_t *output, size_t capacity, const uint8_t *input,
                         size_t input_length, uint16_t proxy_port)
{
    nq_packet_view view;
    size_t output_length;

    if (!output || !input || !nq_parse_packet(input, input_length, &view) || !view.control ||
        view.command != NQ_CCREP_ACCEPT)
        return 0;

    output_length = input_length < 9 ? 9 : input_length;
    if (output_length > capacity || output_length > NQ_NETFLAG_LENGTH_MASK)
        return 0;

    memcpy(output, input, input_length);
    if (output_length > input_length)
        memset(output + input_length, 0, output_length - input_length);
    nq_write_be32(output, NQ_NETFLAG_CTL | (uint32_t)output_length);
    output[4] = NQ_CCREP_ACCEPT;
    nq_write_le32(output + 5, proxy_port);
    return output_length;
}

bool nq_accept_port(const uint8_t *data, size_t length, uint16_t *port)
{
    nq_packet_view view;
    uint32_t value;

    if (!port || !nq_parse_packet(data, length, &view) || !view.control ||
        view.command != NQ_CCREP_ACCEPT)
        return false;

    if (length < 9) {
        *port = 0;
        return true;
    }
    value = nq_read_le32(data + 5);
    if (value > UINT16_MAX)
        return false;
    *port = (uint16_t)value;
    return true;
}

bool nq_supported_protocol(int protocol)
{
    return protocol == NQ_PROTOCOL_NETQUAKE || protocol == NQ_PROTOCOL_FITZQUAKE ||
           protocol == NQ_PROTOCOL_RMQ;
}

const char *nq_protocol_name(int protocol)
{
    switch (protocol) {
    case NQ_PROTOCOL_NETQUAKE:
        return "NetQuake";
    case NQ_PROTOCOL_FITZQUAKE:
        return "FitzQuake";
    case NQ_PROTOCOL_RMQ:
        return "RMQ";
    default:
        return "unknown";
    }
}

int nq_find_server_protocol(const uint8_t *message, size_t length, uint32_t *protocol_flags)
{
    size_t i;

    if (protocol_flags)
        *protocol_flags = 0;
    if (!message)
        return 0;

    for (i = 0; i + 5 <= length; ++i) {
        size_t offset;
        uint32_t value;

        if (message[i] != NQ_SVC_SERVERINFO)
            continue;
        offset = i + 1;
        for (;;) {
            if (offset + 4 > length)
                break;
            value = nq_read_le32(message + offset);
            offset += 4;
            if (value == NQ_PROTOCOL_FTE_PEXT1 || value == NQ_PROTOCOL_FTE_PEXT2) {
                if (offset + 4 > length)
                    break;
                offset += 4; /* extension flags */
                continue;
            }
            if (!nq_supported_protocol((int)value))
                break;
            if (value == NQ_PROTOCOL_RMQ) {
                if (offset + 4 > length)
                    break;
                if (protocol_flags)
                    *protocol_flags = nq_read_le32(message + offset);
            }
            return (int)value;
        }
    }
    return 0;
}
