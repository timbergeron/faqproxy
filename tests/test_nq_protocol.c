#include "nq_protocol.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t make_control(uint8_t *buffer, uint8_t command, const uint8_t *payload,
                           size_t payload_length)
{
    size_t length = 5 + payload_length;

    nq_write_be32(buffer, NQ_NETFLAG_CTL | (uint32_t)length);
    buffer[4] = command;
    memcpy(buffer + 5, payload, payload_length);
    return length;
}

static void test_connect_request(void)
{
    static const uint8_t payload[] = {'Q', 'U', 'A', 'K', 'E', 0, NQ_NET_PROTOCOL_VERSION,
                                      1,   35,  0,   0,   0,   0, 0};
    uint8_t packet[64];
    bool proquake = false;
    size_t length = make_control(packet, NQ_CCREQ_CONNECT, payload, sizeof(payload));

    assert(nq_is_connect_request(packet, length, &proquake));
    assert(proquake);
    packet[11] = 2;
    assert(!nq_is_connect_request(packet, length, NULL));
}

static void test_accept_rewrite(void)
{
    uint8_t input[16];
    uint8_t output[16];
    uint16_t port = 0;
    size_t length;

    nq_write_be32(input, NQ_NETFLAG_CTL | 12);
    input[4] = NQ_CCREP_ACCEPT;
    nq_write_le32(input + 5, 27001);
    input[9] = 1;
    input[10] = 30;
    input[11] = 0x80;
    length = nq_rewrite_accept(output, sizeof(output), input, 12, 26000);
    assert(length == 12);
    assert(nq_accept_port(output, length, &port));
    assert(port == 26000);
    assert(output[9] == 1 && output[10] == 30 && output[11] == 0x80);
}

static void test_packet_view(void)
{
    uint8_t packet[11];
    nq_packet_view view;

    nq_write_be32(packet, NQ_NETFLAG_DATA | NQ_NETFLAG_EOM | sizeof(packet));
    nq_write_be32(packet + 4, 42);
    packet[8] = 1;
    packet[9] = 2;
    packet[10] = 3;
    assert(nq_parse_packet(packet, sizeof(packet), &view));
    assert(!view.control);
    assert(view.sequence == 42);
    assert(view.payload_offset == 8 && view.payload_length == 3);
    packet[3]--;
    assert(!nq_parse_packet(packet, sizeof(packet), &view));
}

static void test_protocol_detection(void)
{
    uint8_t message[32] = {NQ_SVC_SERVERINFO};
    uint32_t flags = 0;

    nq_write_le32(message + 1, NQ_PROTOCOL_NETQUAKE);
    assert(nq_find_server_protocol(message, 5, &flags) == NQ_PROTOCOL_NETQUAKE);
    assert(flags == 0);

    nq_write_le32(message + 1, NQ_PROTOCOL_FITZQUAKE);
    assert(nq_find_server_protocol(message, 5, &flags) == NQ_PROTOCOL_FITZQUAKE);

    nq_write_le32(message + 1, NQ_PROTOCOL_RMQ);
    nq_write_le32(message + 5, NQ_PRFL_FLOATANGLE | NQ_PRFL_SHORTANGLE);
    assert(nq_find_server_protocol(message, 9, &flags) == NQ_PROTOCOL_RMQ);
    assert(flags == (NQ_PRFL_FLOATANGLE | NQ_PRFL_SHORTANGLE));

    memcpy(message + 1, "FTE2", 4);
    nq_write_le32(message + 5, 0x1234);
    nq_write_le32(message + 9, NQ_PROTOCOL_FITZQUAKE);
    assert(nq_find_server_protocol(message, 13, &flags) == NQ_PROTOCOL_FITZQUAKE);
}

int main(void)
{
    test_connect_request();
    test_accept_rewrite();
    test_packet_view();
    test_protocol_detection();
    puts("nq protocol tests passed");
    return 0;
}
