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

    nq_write_be32(input, NQ_NETFLAG_CTL | 8);
    input[4] = NQ_CCREP_ACCEPT;
    assert(!nq_accept_port(input, 8, &port));

    nq_write_be32(input, NQ_NETFLAG_CTL | 5);
    input[4] = NQ_CCREP_ACCEPT;
    assert(nq_accept_port(input, 5, &port));
    assert(port == 0);
    length = nq_rewrite_accept(output, sizeof(output), input, 5, 26000);
    assert(length == 9);
    assert(nq_accept_port(output, length, &port));
    assert(port == 26000);
}

static void test_reject(void)
{
    uint8_t packet[64];
    nq_packet_view view;
    size_t length = nq_make_reject(packet, sizeof(packet), "no room\n");

    assert(length == 14);
    assert(nq_parse_packet(packet, length, &view));
    assert(view.control && view.command == NQ_CCREP_REJECT);
    assert(strcmp((const char *)packet + view.payload_offset, "no room\n") == 0);
    assert(nq_make_reject(packet, 8, "no room\n") == 0);
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

    nq_write_be32(packet, NQ_NETFLAG_CTL | NQ_NETFLAG_DATA | sizeof(packet));
    assert(!nq_parse_packet(packet, sizeof(packet), &view));

    nq_write_be32(packet, NQ_NETFLAG_DATA | NQ_NETFLAG_ACK | sizeof(packet));
    assert(!nq_parse_packet(packet, sizeof(packet), &view));
    nq_write_be32(packet, NQ_NETFLAG_ACK | NQ_NETFLAG_EOM | sizeof(packet));
    assert(!nq_parse_packet(packet, sizeof(packet), &view));
    nq_write_be32(packet, NQ_NETFLAG_ACK | sizeof(packet));
    assert(!nq_parse_packet(packet, sizeof(packet), &view));
    nq_write_be32(packet, NQ_NETFLAG_ACK | 8);
    assert(nq_parse_packet(packet, 8, &view));
}

static void test_protocol_detection(void)
{
    uint8_t message[32] = {NQ_SVC_SERVERINFO};
    uint8_t false_positive[8] = {1, 2, NQ_SVC_SERVERINFO};
    uint32_t flags = 0;
    uint32_t pext2 = 0;

    nq_write_le32(message + 1, NQ_PROTOCOL_NETQUAKE);
    assert(nq_find_server_protocol(message, 5, &flags, &pext2) == NQ_PROTOCOL_NETQUAKE);
    assert(flags == 0);
    assert(pext2 == 0);

    nq_write_le32(message + 1, NQ_PROTOCOL_FITZQUAKE);
    assert(nq_find_server_protocol(message, 5, &flags, &pext2) == NQ_PROTOCOL_FITZQUAKE);

    nq_write_le32(message + 1, NQ_PROTOCOL_RMQ);
    nq_write_le32(message + 5, NQ_PRFL_FLOATANGLE | NQ_PRFL_SHORTANGLE);
    assert(nq_find_server_protocol(message, 9, &flags, &pext2) == NQ_PROTOCOL_RMQ);
    assert(flags == (NQ_PRFL_FLOATANGLE | NQ_PRFL_SHORTANGLE));

    memcpy(message + 1, "FTE2", 4);
    nq_write_le32(message + 5, NQ_PEXT2_PREDINFO | NQ_PEXT2_PRYDONCURSOR);
    nq_write_le32(message + 9, NQ_PROTOCOL_FITZQUAKE);
    assert(nq_find_server_protocol(message, 13, &flags, &pext2) == NQ_PROTOCOL_FITZQUAKE);
    assert(pext2 == (NQ_PEXT2_PREDINFO | NQ_PEXT2_PRYDONCURSOR));

    nq_write_le32(false_positive + 3, NQ_PROTOCOL_NETQUAKE);
    assert(nq_find_server_protocol(false_positive, 7, &flags, &pext2) == 0);
}

static uint32_t fuzz_next(uint32_t *state)
{
    uint32_t value = *state;

    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

static void test_parser_smoke_fuzz(void)
{
    uint8_t input[512];
    uint8_t output[768];
    uint32_t state = UINT32_C(0x5eed1234);
    size_t iteration;

    for (iteration = 0; iteration < 20000; ++iteration) {
        nq_packet_view view;
        uint32_t protocol_flags;
        uint32_t pext2_flags;
        bool proquake;
        size_t length = fuzz_next(&state) % (sizeof(input) + 1);
        size_t i;

        for (i = 0; i < length; ++i)
            input[i] = (uint8_t)fuzz_next(&state);
        (void)nq_parse_packet(input, length, &view);
        (void)nq_is_connect_request(input, length, &proquake);
        (void)nq_rewrite_accept(output, sizeof(output), input, length, 26000);
        (void)nq_find_server_protocol(input, length, &protocol_flags, &pext2_flags);
    }
}

int main(void)
{
    test_connect_request();
    test_accept_rewrite();
    test_reject();
    test_packet_view();
    test_protocol_detection();
    test_parser_smoke_fuzz();
    puts("nq protocol tests passed");
    return 0;
}
