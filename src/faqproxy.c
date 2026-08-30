#define _POSIX_C_SOURCE 200809L

#include "nq_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define FAQPROXY_VERSION "0.1.0"
#define FAQPROXY_MAX_SESSIONS 64
#define FAQPROXY_PACKET_SIZE 65535
#define FAQPROXY_MESSAGE_SIZE 65536
#define FAQPROXY_CONNECT_TIMEOUT_MS UINT64_C(15000)
#define FAQPROXY_QUERY_TIMEOUT_MS UINT64_C(5000)
#define FAQPROXY_POLL_MS 250
#define NQ_PQF_IGNOREPORT 0x80

typedef enum session_state {
    SESSION_FREE = 0,
    SESSION_CONNECTING,
    SESSION_ESTABLISHED,
    SESSION_QUERY
} session_state;

typedef struct reassembly {
    uint8_t data[FAQPROXY_MESSAGE_SIZE];
    size_t length;
    uint32_t last_sequence;
    bool have_sequence;
} reassembly;

typedef struct session {
    session_state state;
    int upstream_fd;
    unsigned long id;
    struct sockaddr_in client;
    struct sockaddr_in server;
    uint64_t last_activity_ms;
    uint64_t bytes_from_client;
    uint64_t bytes_from_server;
    uint64_t packets_from_client;
    uint64_t packets_from_server;
    uint8_t cached_accept[256];
    size_t cached_accept_length;
    bool proquake_requested;
    bool proquake_angles;
    int protocol;
    uint32_t protocol_flags;
    float viewangles[3];
    reassembly server_reliable;
    reassembly client_reliable;
    FILE *demo;
    char demo_path[PATH_MAX];
} session;

typedef struct config {
    struct sockaddr_in listen_address;
    struct sockaddr_in target_address;
    char listen_text[128];
    char target_text[128];
    char record_dir[PATH_MAX];
    unsigned int idle_timeout_seconds;
    int max_sessions;
    int verbose;
} config;

typedef struct app {
    config cfg;
    int listen_fd;
    uint16_t listen_port;
    unsigned long next_session_id;
    session sessions[FAQPROXY_MAX_SESSIONS];
} app;

static volatile sig_atomic_t stop_requested;

static uint64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000) + (uint64_t)now.tv_nsec / UINT64_C(1000000);
}

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void app_log(const app *proxy, int level, const char *format, ...)
{
    va_list arguments;

    if (level > proxy->cfg.verbose)
        return;
    va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
}

static const char *format_address(const struct sockaddr_in *address, char *buffer, size_t capacity)
{
    char host[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &address->sin_addr, host, sizeof(host)))
        snprintf(host, sizeof(host), "?");
    snprintf(buffer, capacity, "%s:%u", host, (unsigned int)ntohs(address->sin_port));
    return buffer;
}

static bool address_equal(const struct sockaddr_in *left, const struct sockaddr_in *right)
{
    return left->sin_family == right->sin_family && left->sin_port == right->sin_port &&
           left->sin_addr.s_addr == right->sin_addr.s_addr;
}

static bool parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !*text)
        return false;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end || value == 0 || value > UINT16_MAX)
        return false;
    *port = (uint16_t)value;
    return true;
}

static bool resolve_endpoint(const char *text, const char *default_host, uint16_t default_port,
                             bool passive, struct sockaddr_in *result, char *display,
                             size_t display_capacity)
{
    char copy[512];
    char *host;
    char *colon;
    uint16_t port = default_port;
    char service[16];
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *candidate;
    int status;

    if (!text || strlen(text) >= sizeof(copy))
        return false;
    memcpy(copy, text, strlen(text) + 1);
    host = copy;
    colon = strrchr(copy, ':');
    if (colon) {
        if (strchr(copy, ':') != colon) {
            fprintf(stderr, "IPv6 endpoints are not supported in this release: %s\n", text);
            return false;
        }
        *colon++ = 0;
        if (!parse_port(colon, &port)) {
            fprintf(stderr, "Invalid UDP port in endpoint: %s\n", text);
            return false;
        }
    }
    if (!*host)
        host = (char *)default_host;

    snprintf(service, sizeof(service), "%u", (unsigned int)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (passive)
        hints.ai_flags = AI_PASSIVE;

    status = getaddrinfo(host, service, &hints, &addresses);
    if (status != 0) {
        fprintf(stderr, "Could not resolve %s: %s\n", text, gai_strerror(status));
        return false;
    }
    candidate = addresses;
    while (candidate && candidate->ai_addrlen < sizeof(struct sockaddr_in))
        candidate = candidate->ai_next;
    if (!candidate) {
        freeaddrinfo(addresses);
        fprintf(stderr, "No IPv4 UDP address found for %s\n", text);
        return false;
    }
    memcpy(result, candidate->ai_addr, sizeof(*result));
    freeaddrinfo(addresses);
    format_address(result, display, display_capacity);
    return true;
}

static bool set_nonblocking(int descriptor)
{
    int flags = fcntl(descriptor, F_GETFL, 0);

    return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int open_listen_socket(const struct sockaddr_in *address, uint16_t *bound_port)
{
    int descriptor;
    int enabled = 1;
    struct sockaddr_in actual;
    socklen_t actual_length = sizeof(actual);

    descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (descriptor < 0)
        return -1;
    (void)setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    if (!set_nonblocking(descriptor) ||
        bind(descriptor, (const struct sockaddr *)address, sizeof(*address)) != 0 ||
        getsockname(descriptor, (struct sockaddr *)&actual, &actual_length) != 0) {
        close(descriptor);
        return -1;
    }
    *bound_port = ntohs(actual.sin_port);
    return descriptor;
}

static int open_upstream_socket(void)
{
    int descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (descriptor < 0)
        return -1;
    if (!set_nonblocking(descriptor)) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static bool send_datagram(int descriptor, const uint8_t *data, size_t length,
                          const struct sockaddr_in *destination)
{
    ssize_t sent;

    do {
        sent = sendto(descriptor, data, length, 0, (const struct sockaddr *)destination,
                      sizeof(*destination));
    } while (sent < 0 && errno == EINTR);
    return sent >= 0 && (size_t)sent == length;
}

static bool ensure_record_directory(const char *path)
{
    struct stat information;

    if (!*path)
        return true;
    if (stat(path, &information) == 0)
        return S_ISDIR(information.st_mode);
    if (errno != ENOENT)
        return false;
    return mkdir(path, 0755) == 0;
}

static bool demo_write_message(session *connection, const uint8_t *message, size_t length)
{
    uint8_t header[16];
    int i;

    if (!connection->demo)
        return true;
    if (length > INT32_MAX)
        return false;
    nq_write_le32(header, (uint32_t)length);
    for (i = 0; i < 3; ++i) {
        uint32_t bits;
        memcpy(&bits, &connection->viewangles[i], sizeof(bits));
        nq_write_le32(header + 4 + (size_t)i * 4, bits);
    }
    if (fwrite(header, 1, sizeof(header), connection->demo) != sizeof(header) ||
        fwrite(message, 1, length, connection->demo) != length)
        return false;
    return true;
}

static void open_demo(app *proxy, session *connection)
{
    time_t current_time;
    struct tm local_time;
    char timestamp[32];
    char address[INET_ADDRSTRLEN];

    if (!proxy->cfg.record_dir[0] || connection->demo)
        return;
    current_time = time(NULL);
    localtime_r(&current_time, &local_time);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &local_time);
    if (!inet_ntop(AF_INET, &connection->client.sin_addr, address, sizeof(address)))
        snprintf(address, sizeof(address), "client");
    snprintf(connection->demo_path, sizeof(connection->demo_path), "%s/faqproxy-%s-%s-%u-%lu.dem",
             proxy->cfg.record_dir, timestamp, address,
             (unsigned int)ntohs(connection->client.sin_port), connection->id);
    connection->demo = fopen(connection->demo_path, "wb");
    if (!connection->demo) {
        app_log(proxy, 0, "session %lu: cannot record %s: %s\n", connection->id,
                connection->demo_path, strerror(errno));
        connection->demo_path[0] = 0;
        return;
    }
    if (fputs("-1\n", connection->demo) < 0) {
        fclose(connection->demo);
        connection->demo = NULL;
        connection->demo_path[0] = 0;
        return;
    }
    app_log(proxy, 0, "session %lu: recording %s\n", connection->id, connection->demo_path);
}

static void close_session(app *proxy, int index, const char *reason)
{
    session *connection = &proxy->sessions[index];

    if (connection->state == SESSION_FREE)
        return;
    app_log(proxy, 0,
            "session %lu: closed (%s), client %llu/%llu packets, server %llu/%llu packets\n",
            connection->id, reason, (unsigned long long)connection->packets_from_client,
            (unsigned long long)connection->bytes_from_client,
            (unsigned long long)connection->packets_from_server,
            (unsigned long long)connection->bytes_from_server);
    if (connection->demo) {
        if (fflush(connection->demo) != 0 || fclose(connection->demo) != 0)
            app_log(proxy, 0, "session %lu: warning: demo write failed\n", connection->id);
    }
    if (connection->upstream_fd >= 0)
        close(connection->upstream_fd);
    memset(connection, 0, sizeof(*connection));
    connection->upstream_fd = -1;
    connection->state = SESSION_FREE;
}

static int find_session(const app *proxy, const struct sockaddr_in *client)
{
    int i;

    for (i = 0; i < proxy->cfg.max_sessions; ++i) {
        if (proxy->sessions[i].state != SESSION_FREE &&
            address_equal(&proxy->sessions[i].client, client))
            return i;
    }
    return -1;
}

static int allocate_session(app *proxy, const struct sockaddr_in *client, session_state state)
{
    int i;
    session *connection;

    for (i = 0; i < proxy->cfg.max_sessions; ++i) {
        if (proxy->sessions[i].state != SESSION_FREE)
            continue;
        connection = &proxy->sessions[i];
        memset(connection, 0, sizeof(*connection));
        connection->upstream_fd = open_upstream_socket();
        if (connection->upstream_fd < 0)
            return -1;
        connection->state = state;
        connection->client = *client;
        connection->server = proxy->cfg.target_address;
        connection->id = ++proxy->next_session_id;
        connection->last_activity_ms = monotonic_milliseconds();
        return i;
    }
    return -1;
}

static void reject_client(app *proxy, const struct sockaddr_in *client, const char *reason)
{
    uint8_t response[512];
    size_t length = nq_make_reject(response, sizeof(response), reason);

    if (length)
        (void)send_datagram(proxy->listen_fd, response, length, client);
}

static void detect_protocol(app *proxy, session *connection, const uint8_t *message, size_t length)
{
    uint32_t flags = 0;
    int protocol = nq_find_server_protocol(message, length, &flags);

    if (!protocol)
        return;
    if (connection->protocol == protocol && connection->protocol_flags == flags)
        return;
    connection->protocol = protocol;
    connection->protocol_flags = flags;
    if (protocol == NQ_PROTOCOL_RMQ)
        app_log(proxy, 0, "session %lu: protocol %d (%s), flags 0x%08x\n", connection->id, protocol,
                nq_protocol_name(protocol), flags);
    else
        app_log(proxy, 0, "session %lu: protocol %d (%s)\n", connection->id, protocol,
                nq_protocol_name(protocol));
}

static float read_angle8(uint8_t value) { return (float)value * (360.0f / 256.0f); }

static float read_angle16(const uint8_t *data)
{
    uint16_t value = (uint16_t)data[0] | (uint16_t)((uint16_t)data[1] << 8);
    return (float)value * (360.0f / 65536.0f);
}

static float read_float_le(const uint8_t *data)
{
    uint32_t bits = nq_read_le32(data);
    float value;

    memcpy(&value, &bits, sizeof(value));
    return value;
}

static void inspect_client_message(session *connection, const uint8_t *message, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        uint8_t command = message[offset++];

        if (command == 0 || command == 1)
            continue;
        if (command == 2)
            return;
        if (command == 4) {
            while (offset < length && message[offset++] != 0)
                ;
            continue;
        }
        if (command == 3) {
            int i;
            size_t angle_bytes;

            if (offset + 4 > length)
                return;
            offset += 4; /* client timestamp */
            if (connection->protocol == NQ_PROTOCOL_RMQ &&
                (connection->protocol_flags & NQ_PRFL_FLOATANGLE))
                angle_bytes = 4;
            else if (connection->protocol == NQ_PROTOCOL_NETQUAKE && !connection->proquake_angles)
                angle_bytes = 1;
            else
                angle_bytes = 2;
            if (offset + angle_bytes * 3 + 8 > length)
                return;
            for (i = 0; i < 3; ++i) {
                if (angle_bytes == 1)
                    connection->viewangles[i] = read_angle8(message[offset]);
                else if (angle_bytes == 2)
                    connection->viewangles[i] = read_angle16(message + offset);
                else
                    connection->viewangles[i] = read_float_le(message + offset);
                offset += angle_bytes;
            }
            offset += 8; /* three moves, buttons, impulse */
            continue;
        }
        return;
    }
}

static void inspect_complete_message(app *proxy, session *connection, bool from_server,
                                     const uint8_t *message, size_t length)
{
    if (from_server) {
        detect_protocol(proxy, connection, message, length);
        if (!demo_write_message(connection, message, length)) {
            app_log(proxy, 0, "session %lu: demo write failed; recording stopped\n",
                    connection->id);
            fclose(connection->demo);
            connection->demo = NULL;
        }
    } else {
        inspect_client_message(connection, message, length);
    }
}

static void inspect_connected_packet(app *proxy, session *connection, bool from_server,
                                     const uint8_t *data, size_t length)
{
    nq_packet_view view;
    reassembly *stream;

    if (!nq_parse_packet(data, length, &view) || view.control)
        return;
    if (view.flags & NQ_NETFLAG_UNRELIABLE) {
        inspect_complete_message(proxy, connection, from_server, data + view.payload_offset,
                                 view.payload_length);
        return;
    }
    if (!(view.flags & NQ_NETFLAG_DATA))
        return;

    stream = from_server ? &connection->server_reliable : &connection->client_reliable;
    if (stream->have_sequence) {
        if (view.sequence == stream->last_sequence)
            return; /* retransmitted while its ACK was in flight */
        if (view.sequence != stream->last_sequence + 1)
            stream->length = 0;
    }
    if (view.payload_length > sizeof(stream->data) - stream->length) {
        stream->length = 0;
        stream->have_sequence = false;
        return;
    }
    memcpy(stream->data + stream->length, data + view.payload_offset, view.payload_length);
    stream->length += view.payload_length;
    stream->last_sequence = view.sequence;
    stream->have_sequence = true;

    if (view.flags & NQ_NETFLAG_EOM) {
        inspect_complete_message(proxy, connection, from_server, stream->data, stream->length);
        stream->length = 0;
    }
}

static void begin_connect(app *proxy, const struct sockaddr_in *client, const uint8_t *data,
                          size_t length, bool proquake_requested)
{
    int index = find_session(proxy, client);
    session *connection;
    char client_text[64];

    if (index >= 0) {
        connection = &proxy->sessions[index];
        if (connection->state == SESSION_CONNECTING) {
            (void)send_datagram(connection->upstream_fd, data, length, &connection->server);
            connection->last_activity_ms = monotonic_milliseconds();
            return;
        }
        if (connection->state == SESSION_ESTABLISHED && connection->cached_accept_length) {
            (void)send_datagram(proxy->listen_fd, connection->cached_accept,
                                connection->cached_accept_length, &connection->client);
            return;
        }
        close_session(proxy, index, "new connection request");
    }

    index = allocate_session(proxy, client, SESSION_CONNECTING);
    if (index < 0) {
        reject_client(proxy, client, "FAQProxy is full.\n");
        return;
    }
    connection = &proxy->sessions[index];
    connection->proquake_requested = proquake_requested;
    if (!send_datagram(connection->upstream_fd, data, length, &connection->server)) {
        reject_client(proxy, client, "FAQProxy could not reach the server.\n");
        close_session(proxy, index, "upstream send failed");
        return;
    }
    connection->packets_from_client++;
    connection->bytes_from_client += length;
    app_log(proxy, 0, "session %lu: %s connecting to %s%s\n", connection->id,
            format_address(client, client_text, sizeof(client_text)), proxy->cfg.target_text,
            proquake_requested ? " (ProQuake extensions requested)" : "");
}

static void begin_query(app *proxy, const struct sockaddr_in *client, const uint8_t *data,
                        size_t length)
{
    int index = find_session(proxy, client);
    session *connection;

    if (index >= 0 && proxy->sessions[index].state != SESSION_QUERY)
        return;
    if (index < 0)
        index = allocate_session(proxy, client, SESSION_QUERY);
    if (index < 0)
        return;
    connection = &proxy->sessions[index];
    if (send_datagram(connection->upstream_fd, data, length, &connection->server)) {
        connection->last_activity_ms = monotonic_milliseconds();
        connection->packets_from_client++;
        connection->bytes_from_client += length;
    }
}

static void handle_client_datagram(app *proxy, const uint8_t *data, size_t length,
                                   const struct sockaddr_in *client)
{
    nq_packet_view view;
    bool proquake_requested = false;
    int index;
    session *connection;

    if (nq_is_connect_request(data, length, &proquake_requested)) {
        begin_connect(proxy, client, data, length, proquake_requested);
        return;
    }

    if (nq_parse_packet(data, length, &view) && view.control) {
        if (view.command == NQ_CCREQ_CONNECT) {
            reject_client(proxy, client, "Incompatible NetQuake connection request.\n");
            return;
        }
        begin_query(proxy, client, data, length);
        return;
    }

    index = find_session(proxy, client);
    if (index < 0)
        return;
    connection = &proxy->sessions[index];
    if (connection->state != SESSION_ESTABLISHED)
        return;
    if (send_datagram(connection->upstream_fd, data, length, &connection->server)) {
        connection->last_activity_ms = monotonic_milliseconds();
        connection->packets_from_client++;
        connection->bytes_from_client += length;
        inspect_connected_packet(proxy, connection, false, data, length);
        app_log(proxy, 2, "session %lu: client -> server %zu bytes\n", connection->id, length);
    }
}

static void drain_client_socket(app *proxy)
{
    uint8_t data[FAQPROXY_PACKET_SIZE];

    for (;;) {
        struct sockaddr_in client;
        socklen_t client_length = sizeof(client);
        ssize_t received = recvfrom(proxy->listen_fd, data, sizeof(data), 0,
                                    (struct sockaddr *)&client, &client_length);
        if (received < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                app_log(proxy, 0, "client receive failed: %s\n", strerror(errno));
            break;
        }
        if (client_length == sizeof(client) && received > 0)
            handle_client_datagram(proxy, data, (size_t)received, &client);
    }
}

static void accept_upstream_connection(app *proxy, int index, const uint8_t *data, size_t length)
{
    session *connection = &proxy->sessions[index];
    uint16_t accepted_port;
    uint8_t rewritten[256];
    size_t rewritten_length;
    bool ignore_port;

    if (!nq_accept_port(data, length, &accepted_port))
        return;
    ignore_port = length >= 12 && data[9] == 1 && (data[11] & NQ_PQF_IGNOREPORT) != 0;
    if (accepted_port && !ignore_port)
        connection->server.sin_port = htons(accepted_port);

    rewritten_length =
        nq_rewrite_accept(rewritten, sizeof(rewritten), data, length, proxy->listen_port);
    if (!rewritten_length)
        return;
    if (!send_datagram(proxy->listen_fd, rewritten, rewritten_length, &connection->client)) {
        close_session(proxy, index, "client accept send failed");
        return;
    }
    memcpy(connection->cached_accept, rewritten, rewritten_length);
    connection->cached_accept_length = rewritten_length;
    connection->proquake_angles = connection->proquake_requested && length >= 10 && data[9] == 1;
    connection->state = SESSION_ESTABLISHED;
    connection->last_activity_ms = monotonic_milliseconds();
    open_demo(proxy, connection);
    app_log(proxy, 0, "session %lu: upstream accepted on UDP port %u\n", connection->id,
            (unsigned int)ntohs(connection->server.sin_port));
}

static void drain_upstream_socket(app *proxy, int index, int expected_fd)
{
    uint8_t data[FAQPROXY_PACKET_SIZE];
    session *connection = &proxy->sessions[index];

    if (connection->state == SESSION_FREE || connection->upstream_fd != expected_fd)
        return;
    for (;;) {
        struct sockaddr_in source;
        socklen_t source_length = sizeof(source);
        ssize_t received = recvfrom(expected_fd, data, sizeof(data), 0, (struct sockaddr *)&source,
                                    &source_length);
        nq_packet_view view;

        if (received < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                close_session(proxy, index, "upstream receive failed");
            return;
        }
        if (source_length != sizeof(source) || !address_equal(&source, &connection->server))
            continue;

        connection->last_activity_ms = monotonic_milliseconds();
        connection->packets_from_server++;
        connection->bytes_from_server += (uint64_t)received;

        if (connection->state == SESSION_CONNECTING &&
            nq_parse_packet(data, (size_t)received, &view) && view.control) {
            if (view.command == NQ_CCREP_ACCEPT) {
                accept_upstream_connection(proxy, index, data, (size_t)received);
                if (proxy->sessions[index].state == SESSION_FREE)
                    return;
                connection = &proxy->sessions[index];
                continue;
            }
            (void)send_datagram(proxy->listen_fd, data, (size_t)received, &connection->client);
            if (view.command == NQ_CCREP_REJECT) {
                close_session(proxy, index, "upstream rejected connection");
                return;
            }
            continue;
        }

        if (!send_datagram(proxy->listen_fd, data, (size_t)received, &connection->client)) {
            close_session(proxy, index, "client send failed");
            return;
        }
        if (connection->state == SESSION_ESTABLISHED)
            inspect_connected_packet(proxy, connection, true, data, (size_t)received);
        app_log(proxy, 2, "session %lu: server -> client %zd bytes\n", connection->id, received);
    }
}

static void expire_sessions(app *proxy)
{
    uint64_t now = monotonic_milliseconds();
    uint64_t idle_limit = (uint64_t)proxy->cfg.idle_timeout_seconds * 1000;
    int i;

    for (i = 0; i < proxy->cfg.max_sessions; ++i) {
        session *connection = &proxy->sessions[i];
        uint64_t limit;

        if (connection->state == SESSION_FREE)
            continue;
        if (connection->state == SESSION_CONNECTING)
            limit = FAQPROXY_CONNECT_TIMEOUT_MS;
        else if (connection->state == SESSION_QUERY)
            limit = FAQPROXY_QUERY_TIMEOUT_MS;
        else
            limit = idle_limit;
        if (limit && now - connection->last_activity_ms > limit)
            close_session(proxy, i, "idle timeout");
    }
}

static int run_proxy(app *proxy)
{
    struct pollfd descriptors[FAQPROXY_MAX_SESSIONS + 1];
    int session_map[FAQPROXY_MAX_SESSIONS + 1];

    while (!stop_requested) {
        nfds_t count = 1;
        int i;
        int status;

        descriptors[0].fd = proxy->listen_fd;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        session_map[0] = -1;
        for (i = 0; i < proxy->cfg.max_sessions; ++i) {
            if (proxy->sessions[i].state == SESSION_FREE)
                continue;
            descriptors[count].fd = proxy->sessions[i].upstream_fd;
            descriptors[count].events = POLLIN;
            descriptors[count].revents = 0;
            session_map[count] = i;
            ++count;
        }

        status = poll(descriptors, count, FAQPROXY_POLL_MS);
        if (status < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "poll failed: %s\n", strerror(errno));
            return 1;
        }
        if (descriptors[0].revents & POLLIN)
            drain_client_socket(proxy);
        for (i = 1; i < (int)count; ++i) {
            if (descriptors[i].revents & POLLIN)
                drain_upstream_socket(proxy, session_map[i], descriptors[i].fd);
            else if (descriptors[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                int index = session_map[i];
                if (proxy->sessions[index].state != SESSION_FREE &&
                    proxy->sessions[index].upstream_fd == descriptors[i].fd)
                    close_session(proxy, index, "upstream socket error");
            }
        }
        expire_sessions(proxy);
    }
    return 0;
}

static void print_usage(FILE *output, const char *program)
{
    fprintf(output,
            "Usage: %s [options] SERVER[:PORT]\n"
            "\n"
            "NetQuake-only protocol-aware UDP proxy for protocols 15, 666, and 999.\n"
            "\n"
            "Options:\n"
            "  -l, --listen ADDRESS[:PORT]  listen endpoint (default 0.0.0.0:26000)\n"
            "  -r, --record-dir DIRECTORY   record each connection as a NetQuake .dem\n"
            "  -m, --max-clients NUMBER     simultaneous sessions, 1-64 (default 32)\n"
            "  -t, --timeout SECONDS        established idle timeout (default 120)\n"
            "  -v, --verbose                verbose logging; repeat for every datagram\n"
            "      --version                print version\n"
            "  -h, --help                   show this help\n",
            program);
}

static bool parse_unsigned(const char *text, unsigned int minimum, unsigned int maximum,
                           unsigned int *result)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end || value < minimum || value > maximum)
        return false;
    *result = (unsigned int)value;
    return true;
}

int main(int argc, char **argv)
{
    static const struct option options[] = {{"listen", required_argument, NULL, 'l'},
                                            {"record-dir", required_argument, NULL, 'r'},
                                            {"max-clients", required_argument, NULL, 'm'},
                                            {"timeout", required_argument, NULL, 't'},
                                            {"verbose", no_argument, NULL, 'v'},
                                            {"version", no_argument, NULL, 1000},
                                            {"help", no_argument, NULL, 'h'},
                                            {NULL, 0, NULL, 0}};
    app *proxy;
    const char *listen_argument = "0.0.0.0:26000";
    unsigned int value;
    int option;
    int exit_status;
    int i;

    proxy = calloc(1, sizeof(*proxy));
    if (!proxy) {
        fprintf(stderr, "Out of memory\n");
        return 1;
    }
    proxy->listen_fd = -1;
    proxy->cfg.max_sessions = 32;
    proxy->cfg.idle_timeout_seconds = 120;
    while ((option = getopt_long(argc, argv, "l:r:m:t:vh", options, NULL)) != -1) {
        switch (option) {
        case 'l':
            listen_argument = optarg;
            break;
        case 'r':
            if (strlen(optarg) >= sizeof(proxy->cfg.record_dir)) {
                fprintf(stderr, "Record directory path is too long\n");
                free(proxy);
                return 2;
            }
            memcpy(proxy->cfg.record_dir, optarg, strlen(optarg) + 1);
            break;
        case 'm':
            if (!parse_unsigned(optarg, 1, FAQPROXY_MAX_SESSIONS, &value)) {
                fprintf(stderr, "--max-clients must be between 1 and %d\n", FAQPROXY_MAX_SESSIONS);
                free(proxy);
                return 2;
            }
            proxy->cfg.max_sessions = (int)value;
            break;
        case 't':
            if (!parse_unsigned(optarg, 0, 86400, &value)) {
                fprintf(stderr, "--timeout must be between 0 and 86400 seconds\n");
                free(proxy);
                return 2;
            }
            proxy->cfg.idle_timeout_seconds = value;
            break;
        case 'v':
            if (proxy->cfg.verbose < 2)
                ++proxy->cfg.verbose;
            break;
        case 1000:
            printf("faqproxy %s\n", FAQPROXY_VERSION);
            free(proxy);
            return 0;
        case 'h':
            print_usage(stdout, argv[0]);
            free(proxy);
            return 0;
        default:
            print_usage(stderr, argv[0]);
            free(proxy);
            return 2;
        }
    }
    if (optind + 1 != argc) {
        print_usage(stderr, argv[0]);
        free(proxy);
        return 2;
    }
    if (!resolve_endpoint(listen_argument, "0.0.0.0", NQ_DEFAULT_PORT, true,
                          &proxy->cfg.listen_address, proxy->cfg.listen_text,
                          sizeof(proxy->cfg.listen_text)) ||
        !resolve_endpoint(argv[optind], NULL, NQ_DEFAULT_PORT, false, &proxy->cfg.target_address,
                          proxy->cfg.target_text, sizeof(proxy->cfg.target_text))) {
        free(proxy);
        return 2;
    }
    if (!ensure_record_directory(proxy->cfg.record_dir)) {
        fprintf(stderr, "Cannot create or use record directory %s: %s\n", proxy->cfg.record_dir,
                strerror(errno));
        free(proxy);
        return 2;
    }

    for (i = 0; i < FAQPROXY_MAX_SESSIONS; ++i)
        proxy->sessions[i].upstream_fd = -1;
    proxy->listen_fd = open_listen_socket(&proxy->cfg.listen_address, &proxy->listen_port);
    if (proxy->listen_fd < 0) {
        fprintf(stderr, "Cannot listen on %s: %s\n", proxy->cfg.listen_text, strerror(errno));
        free(proxy);
        return 1;
    }
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr,
            "faqproxy %s: NetQuake protocols 15/666/999\n"
            "listening on %s, forwarding to %s, max clients %d\n",
            FAQPROXY_VERSION, proxy->cfg.listen_text, proxy->cfg.target_text,
            proxy->cfg.max_sessions);
    if (proxy->cfg.record_dir[0])
        fprintf(stderr, "recording demos in %s\n", proxy->cfg.record_dir);

    exit_status = run_proxy(proxy);
    for (i = 0; i < proxy->cfg.max_sessions; ++i)
        close_session(proxy, i, "proxy shutdown");
    close(proxy->listen_fd);
    fprintf(stderr, "faqproxy stopped\n");
    free(proxy);
    return exit_status;
}
