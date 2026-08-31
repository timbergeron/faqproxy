#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "nq_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <direct.h>
#include <io.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define FAQPROXY_VERSION "0.1.0"
#define FAQPROXY_MAX_SESSIONS 64
#define FAQPROXY_PACKET_SIZE 65535
#define FAQPROXY_MESSAGE_SIZE 65536
#define FAQPROXY_CONNECT_TIMEOUT_MS UINT64_C(15000)
#define FAQPROXY_QUERY_TIMEOUT_MS UINT64_C(5000)
#define FAQPROXY_DUPLICATE_CONNECT_MS UINT64_C(2000)
#define FAQPROXY_POLL_MS 250
#define FAQPROXY_MAX_CONTROL_PACKET 1024
#define FAQPROXY_MAX_QUERY_SESSIONS 16
#define FAQPROXY_MAX_DATAGRAMS_PER_TICK 64
#define FAQPROXY_DEFAULT_MAX_DEMO_MIB 1024
#define FAQPROXY_CONFIRM_TIMEOUT_MS UINT64_C(5000)
#define FAQPROXY_UNCONFIRMED_MAX_PACKETS 256
#define FAQPROXY_UNCONFIRMED_MAX_BYTES (UINT64_C(256) * UINT64_C(1024))
#define FAQPROXY_DEFAULT_CONNECT_RATE 16
#define FAQPROXY_DEFAULT_QUERY_RATE 32
#define FAQPROXY_REJECT_RATE 4
#define FAQPROXY_REJECT_BURST 8
#define NQ_PQF_CHEATFREE 0x01
#define NQ_PQF_IGNOREPORT 0x80
#define NQ_CLC_NOP 1
#define NQ_CLC_DISCONNECT 2
#define NQ_CLC_MOVE 3
#define NQ_CLC_STRINGCMD 4
#define NQ_CLC_ACKFRAME 50

#ifdef _WIN32
typedef SOCKET proxy_socket;
typedef int proxy_socklen;
typedef int proxy_io_size;
typedef WSAPOLLFD proxy_pollfd;
typedef ULONG proxy_nfds;
#define PROXY_INVALID_SOCKET INVALID_SOCKET
#else
typedef int proxy_socket;
typedef socklen_t proxy_socklen;
typedef ssize_t proxy_io_size;
typedef struct pollfd proxy_pollfd;
typedef nfds_t proxy_nfds;
#define PROXY_INVALID_SOCKET (-1)
#endif

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
    bool discard_until_eom;
} reassembly;

typedef struct rate_limiter {
    uint64_t last_refill_ms;
    uint64_t scaled_tokens;
} rate_limiter;

typedef struct session {
    session_state state;
    proxy_socket upstream_fd;
    unsigned long id;
    struct sockaddr_in client;
    struct sockaddr_in server;
    uint64_t last_client_activity_ms;
    uint64_t bytes_from_client;
    uint64_t bytes_from_server;
    uint64_t packets_from_client;
    uint64_t packets_from_server;
    uint64_t accepted_at_ms;
    uint8_t cached_accept[256];
    size_t cached_accept_length;
    bool proquake_requested;
    bool proquake_angles;
    int protocol;
    uint32_t protocol_flags;
    uint32_t pext2_flags;
    uint32_t server_unreliable_sequence;
    uint32_t client_unreliable_sequence;
    bool have_server_unreliable_sequence;
    bool have_client_unreliable_sequence;
    bool client_confirmed;
    unsigned int unconfirmed_packets_from_server;
    uint64_t unconfirmed_bytes_from_server;
    float viewangles[3];
    reassembly server_reliable;
    reassembly client_reliable;
    FILE *demo;
    uint64_t demo_bytes;
    uint64_t demo_limit_bytes;
    bool demo_limit_hit;
    char demo_path[PATH_MAX];
    uint8_t query_command;
} session;

typedef struct config {
    struct sockaddr_in listen_address;
    struct sockaddr_in target_address;
    char listen_text[128];
    char target_text[128];
    char advertise[128];
    char record_dir[PATH_MAX];
    uint64_t max_demo_bytes;
    unsigned int idle_timeout_seconds;
    unsigned int connect_rate;
    unsigned int query_rate;
    int max_sessions;
    int verbose;
    bool allow_player_info;
    bool allow_rcon;
} config;

typedef struct app {
    config cfg;
    proxy_socket listen_fd;
    uint16_t listen_port;
    unsigned long next_session_id;
    rate_limiter connect_limiter;
    rate_limiter query_limiter;
    rate_limiter reject_limiter;
    session sessions[FAQPROXY_MAX_SESSIONS];
} app;

static volatile sig_atomic_t stop_requested;

#if defined(__GNUC__) || defined(__clang__)
static void app_log(const app *proxy, int level, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
#endif

static void shutdown_network(void);

static bool initialize_network(void)
{
#ifdef _WIN32
    WSADATA data;
    int status = WSAStartup(MAKEWORD(2, 2), &data);

    if (status != 0) {
        fprintf(stderr, "Cannot initialize Winsock: error %d\n", status);
        return false;
    }
    if (LOBYTE(data.wVersion) != 2 || HIBYTE(data.wVersion) != 2) {
        fprintf(stderr, "Winsock 2.2 is not available\n");
        WSACleanup();
        return false;
    }
#endif
    if (atexit(shutdown_network) != 0) {
        fprintf(stderr, "Cannot register network cleanup\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }
    return true;
}

static void shutdown_network(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static const char *socket_error_string(void)
{
#ifdef _WIN32
    static char message[256];
    int error = WSAGetLastError();
    DWORD length;

    length = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                            (DWORD)error, 0, message, (DWORD)sizeof(message), NULL);
    while (length > 0 && (message[length - 1] == '\r' || message[length - 1] == '\n'))
        message[--length] = 0;
    if (length == 0)
        snprintf(message, sizeof(message), "Winsock error %d", error);
    return message;
#else
    return strerror(errno);
#endif
}

static bool socket_interrupted(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}

static bool socket_would_block(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static const char *address_error_string(int status)
{
#ifdef _WIN32
    return gai_strerrorA(status);
#else
    return gai_strerror(status);
#endif
}

static void close_socket(proxy_socket descriptor)
{
#ifdef _WIN32
    (void)closesocket(descriptor);
#else
    (void)close(descriptor);
#endif
}

static uint64_t monotonic_milliseconds(void)
{
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000) + (uint64_t)now.tv_nsec / UINT64_C(1000000);
#endif
}

static bool rate_limiter_allow(rate_limiter *limiter, unsigned int rate,
                               unsigned int burst)
{
    uint64_t now;
    uint64_t maximum;
    uint64_t elapsed;
    uint64_t refill;

    if (!rate)
        return true;
    now = monotonic_milliseconds();
    maximum = (uint64_t)burst * UINT64_C(1000);
    if (!limiter->last_refill_ms) {
        limiter->last_refill_ms = now;
        limiter->scaled_tokens = maximum;
    } else {
        elapsed = now >= limiter->last_refill_ms ? now - limiter->last_refill_ms : 0;
        refill = elapsed > maximum / rate ? maximum : elapsed * rate;
        if (limiter->scaled_tokens > maximum - refill)
            limiter->scaled_tokens = maximum;
        else
            limiter->scaled_tokens += refill;
        limiter->last_refill_ms = now;
    }
    if (limiter->scaled_tokens < UINT64_C(1000))
        return false;
    limiter->scaled_tokens -= UINT64_C(1000);
    return true;
}

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static bool install_signal_handlers(void)
{
#ifdef _WIN32
    return signal(SIGINT, handle_signal) != SIG_ERR && signal(SIGTERM, handle_signal) != SIG_ERR &&
           signal(SIGBREAK, handle_signal) != SIG_ERR;
#else
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = handle_signal;
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0)
        return false;
    action.sa_handler = SIG_IGN;
    return sigaction(SIGPIPE, &action, NULL) == 0;
#endif
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

static bool parse_port(const char *text, bool allow_zero, uint16_t *port)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !*text)
        return false;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end || (!allow_zero && value == 0) || value > UINT16_MAX)
        return false;
    *port = (uint16_t)value;
    return true;
}

static bool resolve_endpoint(const char *text, const char *default_host, uint16_t default_port,
                             bool passive, struct sockaddr_in *result, char *display,
                             size_t display_capacity)
{
    char copy[512];
    char *endpoint_host;
    const char *host;
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
    endpoint_host = copy;
    colon = strrchr(copy, ':');
    if (colon) {
        if (strchr(copy, ':') != colon) {
            fprintf(stderr, "IPv6 endpoints are not supported in this release: %s\n", text);
            return false;
        }
        *colon++ = 0;
        if (!parse_port(colon, passive, &port)) {
            fprintf(stderr, "Invalid UDP port in endpoint: %s\n", text);
            return false;
        }
    }
    if (!*endpoint_host && !default_host) {
        fprintf(stderr, "Endpoint is missing a host: %s\n", text);
        return false;
    }
    host = *endpoint_host ? endpoint_host : default_host;

    snprintf(service, sizeof(service), "%u", (unsigned int)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (passive)
        hints.ai_flags = AI_PASSIVE;

    status = getaddrinfo(host, service, &hints, &addresses);
    if (status != 0) {
        fprintf(stderr, "Could not resolve %s: %s\n", text, address_error_string(status));
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

static bool normalize_advertise(const char *text, uint16_t default_port, char *output,
                                size_t capacity)
{
    const char *colon;
    size_t i;
    int written;

    if (!text || !*text)
        return false;
    for (i = 0; text[i]; ++i) {
        if ((unsigned char)text[i] <= 32)
            return false;
    }
    colon = strrchr(text, ':');
    if (colon) {
        uint16_t ignored_port;

        if (colon == text || strchr(text, ':') != colon || !parse_port(colon + 1, false,
                                                                       &ignored_port))
            return false;
        written = snprintf(output, capacity, "%s", text);
    } else {
        written = snprintf(output, capacity, "%s:%u", text, (unsigned int)default_port);
    }
    return written >= 0 && (size_t)written < capacity;
}

static bool set_close_on_exec(int descriptor)
{
#ifdef _WIN32
    intptr_t native_handle = _get_osfhandle(descriptor);

    return native_handle != -1 &&
           SetHandleInformation((HANDLE)native_handle, HANDLE_FLAG_INHERIT, 0) != 0;
#else
    int descriptor_flags = fcntl(descriptor, F_GETFD, 0);

    return descriptor_flags >= 0 && fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0;
#endif
}

static bool configure_socket(proxy_socket descriptor)
{
#ifdef _WIN32
    u_long nonblocking = 1;

    return ioctlsocket(descriptor, (long)FIONBIO, &nonblocking) == 0 &&
           SetHandleInformation((HANDLE)descriptor, HANDLE_FLAG_INHERIT, 0) != 0;
#else
    int flags = fcntl(descriptor, F_GETFL, 0);

    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0)
        return false;
    return set_close_on_exec(descriptor);
#endif
}

static proxy_socket open_listen_socket(const struct sockaddr_in *address, uint16_t *bound_port)
{
    proxy_socket descriptor;
    struct sockaddr_in actual;
    proxy_socklen actual_length = (proxy_socklen)sizeof(actual);

    descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (descriptor == PROXY_INVALID_SOCKET)
        return PROXY_INVALID_SOCKET;
#ifdef _WIN32
    {
        int enabled = 1;

        if (setsockopt(descriptor, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&enabled,
                       (proxy_socklen)sizeof(enabled)) != 0) {
            close_socket(descriptor);
            return PROXY_INVALID_SOCKET;
        }
    }
#endif
    if (!configure_socket(descriptor) ||
        bind(descriptor, (const struct sockaddr *)address, (proxy_socklen)sizeof(*address)) != 0 ||
        getsockname(descriptor, (struct sockaddr *)&actual, &actual_length) != 0) {
        close_socket(descriptor);
        return PROXY_INVALID_SOCKET;
    }
    *bound_port = ntohs(actual.sin_port);
    return descriptor;
}

static proxy_socket open_upstream_socket(const struct sockaddr_in *server)
{
    proxy_socket descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (descriptor == PROXY_INVALID_SOCKET)
        return PROXY_INVALID_SOCKET;
    if (!configure_socket(descriptor) ||
        connect(descriptor, (const struct sockaddr *)server, (proxy_socklen)sizeof(*server)) != 0) {
        close_socket(descriptor);
        return PROXY_INVALID_SOCKET;
    }
    return descriptor;
}

static bool send_datagram(proxy_socket descriptor, const uint8_t *data, size_t length,
                          const struct sockaddr_in *destination)
{
    proxy_io_size sent;

    if (length > INT_MAX)
        return false;

    do {
#ifdef _WIN32
        sent = sendto(descriptor, (const char *)data, (int)length, 0,
                      (const struct sockaddr *)destination, (proxy_socklen)sizeof(*destination));
#else
        sent = sendto(descriptor, data, length, 0, (const struct sockaddr *)destination,
                      (proxy_socklen)sizeof(*destination));
#endif
    } while (sent < 0 && socket_interrupted());
    return sent >= 0 && (size_t)sent == length;
}

static bool send_upstream(proxy_socket descriptor, const uint8_t *data, size_t length)
{
    proxy_io_size sent;

    if (length > INT_MAX)
        return false;
    do {
#ifdef _WIN32
        sent = send(descriptor, (const char *)data, (int)length, 0);
#else
        sent = send(descriptor, data, length, 0);
#endif
    } while (sent < 0 && socket_interrupted());
    return sent >= 0 && (size_t)sent == length;
}

static bool connect_upstream(proxy_socket descriptor, const struct sockaddr_in *server)
{
    return connect(descriptor, (const struct sockaddr *)server,
                   (proxy_socklen)sizeof(*server)) == 0;
}

static bool local_time_value(time_t value, struct tm *result)
{
#ifdef _WIN32
    return localtime_s(result, &value) == 0;
#else
    return localtime_r(&value, result) != NULL;
#endif
}

static int make_directory(const char *path)
{
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0700);
#endif
}

static int close_file_descriptor(int descriptor)
{
#ifdef _WIN32
    return _close(descriptor);
#else
    return close(descriptor);
#endif
}

static FILE *file_descriptor_stream(int descriptor)
{
#ifdef _WIN32
    return _fdopen(descriptor, "wb");
#else
    return fdopen(descriptor, "wb");
#endif
}

static int delete_file(const char *path)
{
#ifdef _WIN32
    return _unlink(path);
#else
    return unlink(path);
#endif
}

static bool ensure_one_directory(const char *path, bool reject_symlink)
{
    struct stat information;
    int status;

#ifdef _WIN32
    (void)reject_symlink;
    status = stat(path, &information);
#else
    status = reject_symlink ? lstat(path, &information) : stat(path, &information);
#endif
    if (status == 0) {
#ifndef _WIN32
        if (reject_symlink && S_ISLNK(information.st_mode)) {
            errno = ELOOP;
            return false;
        }
#endif
        if (S_ISDIR(information.st_mode))
            return true;
        errno = ENOTDIR;
        return false;
    }
    if (errno != ENOENT)
        return false;
    return make_directory(path) == 0;
}

static bool ensure_record_directory(const char *path)
{
    char copy[PATH_MAX];
    char *cursor;
    size_t length;

    if (!*path)
        return true;
    length = strlen(path);
    if (length >= sizeof(copy)) {
        errno = ENAMETOOLONG;
        return false;
    }
    memcpy(copy, path, length + 1);
#ifdef _WIN32
    while (length > 1 && (copy[length - 1] == '/' || copy[length - 1] == '\\') &&
           !(length == 3 && copy[1] == ':'))
        copy[--length] = 0;
#else
    while (length > 1 && copy[length - 1] == '/')
        copy[--length] = 0;
#endif
    cursor = copy;
#ifdef _WIN32
    if (copy[0] && copy[1] == ':')
        cursor = copy + 2;
#else
    if (copy[0] == '/')
        cursor = copy + 1;
#endif
    for (; *cursor; ++cursor) {
        bool separator = *cursor == '/';
#ifdef _WIN32
        separator = separator || *cursor == '\\';
#endif
        if (separator && cursor > copy && cursor[-1] != ':') {
            char saved = *cursor;

            *cursor = 0;
            if (!ensure_one_directory(copy, false))
                return false;
            *cursor = saved;
        }
    }
    return ensure_one_directory(copy, true);
}

static bool demo_write_message(session *connection, const uint8_t *message, size_t length)
{
    uint8_t header[16];
    int i;

    if (!connection->demo)
        return true;
    if (length > INT32_MAX)
        return false;
    if (connection->demo_limit_bytes) {
        uint64_t record_bytes = (uint64_t)sizeof(header) + (uint64_t)length;

        if (record_bytes > connection->demo_limit_bytes ||
            connection->demo_bytes > connection->demo_limit_bytes - record_bytes) {
            connection->demo_limit_hit = true;
            return false;
        }
    }
    nq_write_le32(header, (uint32_t)length);
    for (i = 0; i < 3; ++i) {
        uint32_t bits;
        memcpy(&bits, &connection->viewangles[i], sizeof(bits));
        nq_write_le32(header + 4 + (size_t)i * 4, bits);
    }
    if (fwrite(header, 1, sizeof(header), connection->demo) != sizeof(header) ||
        fwrite(message, 1, length, connection->demo) != length)
        return false;
    connection->demo_bytes += sizeof(header) + length;
    return true;
}

static bool close_demo(session *connection)
{
    bool success = true;

    if (!connection->demo)
        return true;
    if (fflush(connection->demo) != 0)
        success = false;
    if (fclose(connection->demo) != 0)
        success = false;
    connection->demo = NULL;
    return success;
}

static void open_demo(app *proxy, session *connection)
{
    time_t current_time;
    struct tm local_time;
    char timestamp[32];
    char address[INET_ADDRSTRLEN];
    int descriptor;
    int open_flags = O_WRONLY | O_CREAT | O_EXCL;
    int path_length;
    bool created = false;

    if (!proxy->cfg.record_dir[0] || connection->demo)
        return;
    current_time = time(NULL);
    if (!local_time_value(current_time, &local_time) ||
        strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &local_time) == 0) {
        app_log(proxy, 0, "session %lu: cannot create demo timestamp\n", connection->id);
        return;
    }
    if (!inet_ntop(AF_INET, &connection->client.sin_addr, address, sizeof(address)))
        snprintf(address, sizeof(address), "client");
    path_length =
        snprintf(connection->demo_path, sizeof(connection->demo_path),
                 "%s/faqproxy-%s-%s-%u-%lu.dem", proxy->cfg.record_dir, timestamp, address,
                 (unsigned int)ntohs(connection->client.sin_port), connection->id);
    if (path_length < 0 || (size_t)path_length >= sizeof(connection->demo_path)) {
        app_log(proxy, 0, "session %lu: demo path is too long\n", connection->id);
        connection->demo_path[0] = 0;
        return;
    }
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    open_flags |= O_NOFOLLOW;
#endif
#ifdef _WIN32
    open_flags |= _O_BINARY | _O_NOINHERIT;
    descriptor = _open(connection->demo_path, open_flags, _S_IREAD | _S_IWRITE);
#else
    descriptor = open(connection->demo_path, open_flags, 0640);
#endif
    if (descriptor >= 0)
        created = true;
    if (descriptor >= 0 && !set_close_on_exec(descriptor)) {
        int saved_error = errno;

        (void)close_file_descriptor(descriptor);
        errno = saved_error;
        descriptor = -1;
    }
    if (descriptor >= 0)
        connection->demo = file_descriptor_stream(descriptor);
    if (!connection->demo) {
        int saved_error = errno;

        if (descriptor >= 0)
            (void)close_file_descriptor(descriptor);
        if (created)
            (void)delete_file(connection->demo_path);
        app_log(proxy, 0, "session %lu: cannot record %s: %s\n", connection->id,
                connection->demo_path, strerror(saved_error));
        connection->demo_path[0] = 0;
        return;
    }
    if (fputs("-1\n", connection->demo) < 0) {
        (void)close_demo(connection);
        (void)delete_file(connection->demo_path);
        connection->demo_path[0] = 0;
        return;
    }
    connection->demo_bytes = 3;
    connection->demo_limit_bytes = proxy->cfg.max_demo_bytes;
    app_log(proxy, 0, "session %lu: recording %s\n", connection->id, connection->demo_path);
}

static void close_session(app *proxy, int index, const char *reason)
{
    session *connection = &proxy->sessions[index];
    int log_level;

    if (connection->state == SESSION_FREE)
        return;
    log_level = connection->state == SESSION_QUERY ? 1 : 0;
    app_log(proxy, log_level,
            "session %lu: closed (%s), client %llu packets/%llu bytes, "
            "server %llu packets/%llu bytes\n",
            connection->id, reason, (unsigned long long)connection->packets_from_client,
            (unsigned long long)connection->bytes_from_client,
            (unsigned long long)connection->packets_from_server,
            (unsigned long long)connection->bytes_from_server);
    if (!close_demo(connection))
        app_log(proxy, 0, "session %lu: warning: demo write failed\n", connection->id);
    if (connection->upstream_fd != PROXY_INVALID_SOCKET)
        close_socket(connection->upstream_fd);
    memset(connection, 0, sizeof(*connection));
    connection->upstream_fd = PROXY_INVALID_SOCKET;
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
        connection->upstream_fd = open_upstream_socket(&proxy->cfg.target_address);
        if (connection->upstream_fd == PROXY_INVALID_SOCKET)
            return -1;
        connection->state = state;
        connection->client = *client;
        connection->server = proxy->cfg.target_address;
        connection->id = ++proxy->next_session_id;
        connection->last_client_activity_ms = monotonic_milliseconds();
        return i;
    }
    return -1;
}

static bool restart_session(app *proxy, int index, bool proquake_requested)
{
    session *connection = &proxy->sessions[index];
    proxy_socket upstream_fd = connection->upstream_fd;
    struct sockaddr_in client = connection->client;
    unsigned long previous_id = connection->id;

    if (!close_demo(connection))
        app_log(proxy, 0, "session %lu: warning: demo write failed during reconnect\n",
                previous_id);
    if (!connect_upstream(upstream_fd, &proxy->cfg.target_address)) {
        close_session(proxy, index, "cannot reconnect upstream control port");
        return false;
    }
    memset(connection, 0, sizeof(*connection));
    connection->state = SESSION_CONNECTING;
    connection->upstream_fd = upstream_fd;
    connection->id = ++proxy->next_session_id;
    connection->client = client;
    connection->server = proxy->cfg.target_address;
    connection->last_client_activity_ms = monotonic_milliseconds();
    connection->proquake_requested = proquake_requested;
    app_log(proxy, 0, "session %lu: reconnecting as session %lu with the same upstream port\n",
            previous_id, connection->id);
    return true;
}

static bool query_command_allowed(const app *proxy, uint8_t command)
{
    if (command == NQ_CCREQ_SERVER_INFO)
        return proxy->cfg.advertise[0] != 0;
    if (command == NQ_CCREQ_PLAYER_INFO)
        return proxy->cfg.allow_player_info;
    if (command == NQ_CCREQ_RULE_INFO)
        return true;
    return command == NQ_CCREQ_RCON && proxy->cfg.allow_rcon;
}

static bool valid_query_request(const app *proxy, const uint8_t *data, size_t length,
                                const nq_packet_view *view)
{
    const uint8_t *terminator;

    if (length > FAQPROXY_MAX_CONTROL_PACKET || !query_command_allowed(proxy, view->command))
        return false;
    if (view->command == NQ_CCREQ_SERVER_INFO) {
        static const uint8_t payload[] = {'Q', 'U', 'A', 'K', 'E', 0,
                                          NQ_NET_PROTOCOL_VERSION};

        return view->payload_length == sizeof(payload) &&
               memcmp(data + view->payload_offset, payload, sizeof(payload)) == 0;
    }
    if (view->command == NQ_CCREQ_PLAYER_INFO)
        return view->payload_length == 1;
    if (view->command == NQ_CCREQ_RULE_INFO) {
        terminator = memchr(data + view->payload_offset, 0, view->payload_length);
        return terminator && terminator == data + length - 1;
    }
    if (view->command == NQ_CCREQ_RCON) {
        const uint8_t *password_end =
            memchr(data + view->payload_offset, 0, view->payload_length);

        if (!password_end || password_end == data + length - 1)
            return false;
        terminator = memchr(password_end + 1, 0, (size_t)(data + length - password_end - 1));
        return terminator && terminator == data + length - 1;
    }
    return false;
}

static int query_session_count(const app *proxy)
{
    int count = 0;
    int i;

    for (i = 0; i < proxy->cfg.max_sessions; ++i) {
        if (proxy->sessions[i].state == SESSION_QUERY)
            ++count;
    }
    return count;
}

static int query_session_limit(const app *proxy)
{
    int limit = proxy->cfg.max_sessions / 4;

    if (limit < 1)
        limit = 1;
    if (limit > FAQPROXY_MAX_QUERY_SESSIONS)
        limit = FAQPROXY_MAX_QUERY_SESSIONS;
    return limit;
}

static void reject_client(app *proxy, const struct sockaddr_in *client, const char *reason)
{
    uint8_t response[512];
    size_t length = nq_make_reject(response, sizeof(response), reason);

    if (length && rate_limiter_allow(&proxy->reject_limiter, FAQPROXY_REJECT_RATE,
                                     FAQPROXY_REJECT_BURST))
        (void)send_datagram(proxy->listen_fd, response, length, client);
}

static void detect_protocol(app *proxy, session *connection, const uint8_t *message, size_t length)
{
    uint32_t flags = 0;
    uint32_t pext2_flags = 0;
    int protocol;

    if (connection->protocol)
        return;
    protocol = nq_find_server_protocol(message, length, &flags, &pext2_flags);
    if (!protocol)
        return;
    connection->protocol = protocol;
    connection->protocol_flags = flags;
    connection->pext2_flags = pext2_flags;
    if (protocol == NQ_PROTOCOL_RMQ && pext2_flags)
        app_log(proxy, 0, "session %lu: protocol %d (%s), flags 0x%08x, FTE2 flags 0x%08x\n",
                connection->id, protocol, nq_protocol_name(protocol), flags, pext2_flags);
    else if (protocol == NQ_PROTOCOL_RMQ)
        app_log(proxy, 0, "session %lu: protocol %d (%s), flags 0x%08x\n", connection->id, protocol,
                nq_protocol_name(protocol), flags);
    else if (pext2_flags)
        app_log(proxy, 0, "session %lu: protocol %d (%s), FTE2 flags 0x%08x\n", connection->id,
                protocol, nq_protocol_name(protocol), pext2_flags);
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

        if (command == 0)
            return;
        if (command == NQ_CLC_NOP)
            continue;
        if (command == NQ_CLC_DISCONNECT)
            return;
        if (command == NQ_CLC_ACKFRAME) {
            if (offset + 4 > length)
                return;
            offset += 4;
            continue;
        }
        if (command == NQ_CLC_STRINGCMD) {
            while (offset < length && message[offset++] != 0)
                ;
            continue;
        }
        if (command == NQ_CLC_MOVE) {
            int i;
            size_t angle_bytes;

            if (connection->pext2_flags & NQ_PEXT2_PREDINFO) {
                if (offset + 6 > length)
                    return;
                offset += 6; /* command sequence and client timestamp */
            } else if (offset + 4 <= length) {
                offset += 4; /* client timestamp */
            } else {
                return;
            }
            if (connection->protocol == NQ_PROTOCOL_RMQ &&
                (connection->protocol_flags & NQ_PRFL_FLOATANGLE))
                angle_bytes = 4;
            else if (connection->protocol == NQ_PROTOCOL_NETQUAKE && !connection->proquake_angles &&
                     !(connection->pext2_flags & NQ_PEXT2_PREDINFO))
                angle_bytes = 1;
            else
                angle_bytes = 2;
            if (offset + angle_bytes * 3 > length)
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
            return;
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
            if (connection->demo_limit_hit)
                app_log(proxy, 0, "session %lu: demo size limit reached; recording stopped\n",
                        connection->id);
            else
                app_log(proxy, 0, "session %lu: demo write failed; recording stopped\n",
                        connection->id);
            (void)close_demo(connection);
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
        uint32_t *next_sequence = from_server ? &connection->server_unreliable_sequence
                                              : &connection->client_unreliable_sequence;
        bool *have_sequence = from_server ? &connection->have_server_unreliable_sequence
                                          : &connection->have_client_unreliable_sequence;

        if (*have_sequence && view.sequence < *next_sequence)
            return;
        *next_sequence = view.sequence + 1;
        *have_sequence = true;
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
        if (view.sequence != stream->last_sequence + 1) {
            stream->length = 0;
            stream->discard_until_eom = true;
        }
    }
    stream->last_sequence = view.sequence;
    stream->have_sequence = true;
    if (stream->discard_until_eom) {
        if (view.flags & NQ_NETFLAG_EOM)
            stream->discard_until_eom = false;
        return;
    }
    if (view.payload_length > sizeof(stream->data) - stream->length) {
        stream->length = 0;
        stream->discard_until_eom = !(view.flags & NQ_NETFLAG_EOM);
        return;
    }
    memcpy(stream->data + stream->length, data + view.payload_offset, view.payload_length);
    stream->length += view.payload_length;
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
    uint64_t now = monotonic_milliseconds();

    if (index >= 0) {
        connection = &proxy->sessions[index];
        if (connection->state == SESSION_CONNECTING) {
            if (send_upstream(connection->upstream_fd, data, length)) {
                connection->packets_from_client++;
                connection->bytes_from_client += length;
            } else {
                app_log(proxy, 1, "session %lu: retry send failed: %s\n", connection->id,
                        socket_error_string());
            }
            connection->last_client_activity_ms = now;
            return;
        }
        if (connection->state == SESSION_ESTABLISHED && connection->cached_accept_length &&
            connection->accepted_at_ms &&
            now - connection->accepted_at_ms < FAQPROXY_DUPLICATE_CONNECT_MS) {
            (void)send_datagram(proxy->listen_fd, connection->cached_accept,
                                connection->cached_accept_length, &connection->client);
            connection->last_client_activity_ms = now;
            return;
        }
    }

    if (!rate_limiter_allow(&proxy->connect_limiter, proxy->cfg.connect_rate,
                            proxy->cfg.connect_rate * 2))
        return;

    if (index >= 0) {
        connection = &proxy->sessions[index];
        if (connection->state == SESSION_ESTABLISHED && connection->cached_accept_length) {
            if (!restart_session(proxy, index, proquake_requested))
                index = -1;
        } else {
            close_session(proxy, index, "new connection request");
            index = -1;
        }
    }

    if (index < 0)
        index = allocate_session(proxy, client, SESSION_CONNECTING);
    if (index < 0) {
        reject_client(proxy, client, "FAQProxy is full.\n");
        return;
    }
    connection = &proxy->sessions[index];
    connection->proquake_requested = proquake_requested;
    if (!send_upstream(connection->upstream_fd, data, length)) {
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
                        size_t length, uint8_t command)
{
    int index = find_session(proxy, client);
    session *connection;

    if (index >= 0 && proxy->sessions[index].state != SESSION_QUERY)
        return;
    if (index >= 0 && proxy->sessions[index].query_command != command)
        return;
    if (!rate_limiter_allow(&proxy->query_limiter, proxy->cfg.query_rate,
                            proxy->cfg.query_rate * 2))
        return;
    if (index < 0 && query_session_count(proxy) >= query_session_limit(proxy))
        return;
    if (index < 0)
        index = allocate_session(proxy, client, SESSION_QUERY);
    if (index < 0)
        return;
    connection = &proxy->sessions[index];
    connection->query_command = command;
    if (send_upstream(connection->upstream_fd, data, length)) {
        connection->last_client_activity_ms = monotonic_milliseconds();
        connection->packets_from_client++;
        connection->bytes_from_client += length;
    } else {
        app_log(proxy, 1, "session %lu: control query send failed: %s\n", connection->id,
                socket_error_string());
        close_session(proxy, index, "control query send failed");
    }
}

static void handle_client_datagram(app *proxy, const uint8_t *data, size_t length,
                                   const struct sockaddr_in *client)
{
    nq_packet_view view;
    bool proquake_requested = false;
    bool parsed;
    bool confirms_client;
    int index;
    session *connection;

    parsed = nq_parse_packet(data, length, &view);
    if (parsed && view.control && length > FAQPROXY_MAX_CONTROL_PACKET) {
        app_log(proxy, 1, "ignored oversized control request (%llu bytes)\n",
                (unsigned long long)length);
        return;
    }
    if (nq_is_connect_request(data, length, &proquake_requested)) {
        begin_connect(proxy, client, data, length, proquake_requested);
        return;
    }

    if (parsed && view.control) {
        if (view.command == NQ_CCREQ_CONNECT) {
            if (length >= 12)
                reject_client(proxy, client, "Incompatible NetQuake connection request.\n");
            return;
        }
        if (!valid_query_request(proxy, data, length, &view)) {
            app_log(proxy, 1, "ignored unsupported control request 0x%02x\n", view.command);
            return;
        }
        begin_query(proxy, client, data, length, view.command);
        return;
    }

    if (!parsed)
        return;

    index = find_session(proxy, client);
    if (index < 0)
        return;
    connection = &proxy->sessions[index];
    if (connection->state != SESSION_ESTABLISHED)
        return;
    confirms_client = (view.flags & NQ_NETFLAG_ACK) != 0 &&
                      connection->server_reliable.have_sequence &&
                      view.sequence == connection->server_reliable.last_sequence;
    if (send_upstream(connection->upstream_fd, data, length)) {
        connection->last_client_activity_ms = monotonic_milliseconds();
        if (confirms_client)
            connection->client_confirmed = true;
        connection->packets_from_client++;
        connection->bytes_from_client += length;
        inspect_connected_packet(proxy, connection, false, data, length);
        app_log(proxy, 2, "session %lu: client -> server %llu bytes\n", connection->id,
                (unsigned long long)length);
    } else {
        app_log(proxy, 1, "session %lu: client datagram send failed: %s\n", connection->id,
                socket_error_string());
    }
}

static void drain_client_socket(app *proxy)
{
    uint8_t data[FAQPROXY_PACKET_SIZE];
    unsigned int processed;

    for (processed = 0; processed < FAQPROXY_MAX_DATAGRAMS_PER_TICK; ++processed) {
        struct sockaddr_in client;
        proxy_socklen client_length = (proxy_socklen)sizeof(client);
#ifdef _WIN32
        proxy_io_size received = recvfrom(proxy->listen_fd, (char *)data, (int)sizeof(data), 0,
                                          (struct sockaddr *)&client, &client_length);
#else
        proxy_io_size received = recvfrom(proxy->listen_fd, data, sizeof(data), 0,
                                          (struct sockaddr *)&client, &client_length);
#endif
        if (received < 0) {
            if (socket_interrupted())
                continue;
            if (!socket_would_block())
                app_log(proxy, 0, "client receive failed: %s\n", socket_error_string());
            break;
        }
        if (client_length == (proxy_socklen)sizeof(client) && received > 0)
            handle_client_datagram(proxy, data, (size_t)received, &client);
    }
}

static bool accept_upstream_connection(app *proxy, session *connection, const uint8_t *data,
                                       size_t length)
{
    uint16_t accepted_port;
    uint8_t rewritten[256];
    size_t rewritten_length;
    bool ignore_port;

    if (!nq_accept_port(data, length, &accepted_port))
        return false;
    ignore_port = length >= 12 && data[9] == 1 && (data[11] & NQ_PQF_IGNOREPORT) != 0;
    if (accepted_port && !ignore_port) {
        struct sockaddr_in accepted_server = connection->server;

        accepted_server.sin_port = htons(accepted_port);
        if (!connect_upstream(connection->upstream_fd, &accepted_server)) {
            app_log(proxy, 0, "session %lu: cannot switch to upstream UDP port %u: %s\n",
                    connection->id, (unsigned int)accepted_port, socket_error_string());
            return false;
        }
        connection->server = accepted_server;
    }

    rewritten_length =
        nq_rewrite_accept(rewritten, sizeof(rewritten), data, length, proxy->listen_port);
    if (!rewritten_length)
        return false;
    if (!send_datagram(proxy->listen_fd, rewritten, rewritten_length, &connection->client)) {
        app_log(proxy, 0, "session %lu: client accept send failed: %s\n", connection->id,
                socket_error_string());
        return false;
    }
    memcpy(connection->cached_accept, rewritten, rewritten_length);
    connection->cached_accept_length = rewritten_length;
    connection->proquake_angles = connection->proquake_requested && length >= 10 && data[9] == 1;
    connection->state = SESSION_ESTABLISHED;
    connection->accepted_at_ms = monotonic_milliseconds();
    open_demo(proxy, connection);
    app_log(proxy, 0, "session %lu: upstream accepted on UDP port %u\n", connection->id,
            (unsigned int)ntohs(connection->server.sin_port));
    return true;
}

static uint8_t expected_query_reply(uint8_t request)
{
    switch (request) {
    case NQ_CCREQ_SERVER_INFO:
        return NQ_CCREP_SERVER_INFO;
    case NQ_CCREQ_PLAYER_INFO:
        return NQ_CCREP_PLAYER_INFO;
    case NQ_CCREQ_RULE_INFO:
        return NQ_CCREP_RULE_INFO;
    case NQ_CCREQ_RCON:
        return NQ_CCREP_RCON;
    default:
        return 0;
    }
}

static size_t rewrite_server_info(const app *proxy, uint8_t *output, size_t capacity,
                                  const uint8_t *input, size_t input_length)
{
    nq_packet_view view;
    const uint8_t *terminator;
    size_t old_address_length;
    size_t new_address_length;
    size_t suffix_length;
    size_t output_length;

    if (!nq_parse_packet(input, input_length, &view) || !view.control ||
        view.command != NQ_CCREP_SERVER_INFO)
        return 0;
    terminator = memchr(input + view.payload_offset, 0, view.payload_length);
    if (!terminator)
        return 0;
    old_address_length = (size_t)(terminator - (input + view.payload_offset)) + 1;
    new_address_length = strlen(proxy->cfg.advertise) + 1;
    suffix_length = view.payload_length - old_address_length;
    output_length = view.payload_offset + new_address_length + suffix_length;
    if (output_length > capacity || output_length > NQ_NETFLAG_LENGTH_MASK)
        return 0;
    nq_write_be32(output, NQ_NETFLAG_CTL | (uint32_t)output_length);
    output[4] = NQ_CCREP_SERVER_INFO;
    memcpy(output + view.payload_offset, proxy->cfg.advertise, new_address_length);
    memcpy(output + view.payload_offset + new_address_length, terminator + 1, suffix_length);
    return output_length;
}

static void drain_upstream_socket(app *proxy, int index, proxy_socket expected_fd)
{
    uint8_t data[FAQPROXY_PACKET_SIZE];
    session *connection = &proxy->sessions[index];
    unsigned int processed;

    if (connection->state == SESSION_FREE || connection->upstream_fd != expected_fd)
        return;
    for (processed = 0; processed < FAQPROXY_MAX_DATAGRAMS_PER_TICK; ++processed) {
#ifdef _WIN32
        proxy_io_size received = recv(expected_fd, (char *)data, (int)sizeof(data), 0);
#else
        proxy_io_size received = recv(expected_fd, data, sizeof(data), 0);
#endif
        nq_packet_view view;

        if (received < 0) {
            if (socket_interrupted())
                continue;
            if (!socket_would_block())
                close_session(proxy, index, "upstream receive failed");
            return;
        }
        connection->packets_from_server++;
        connection->bytes_from_server += (uint64_t)received;

        if (connection->state == SESSION_CONNECTING &&
            nq_parse_packet(data, (size_t)received, &view) && view.control) {
            if (view.command == NQ_CCREP_ACCEPT) {
                if ((size_t)received >= 12 && data[9] == 1 &&
                    (data[11] & NQ_PQF_CHEATFREE) != 0) {
                    reject_client(proxy, &connection->client,
                                  "ProQuake cheat-free is incompatible with a UDP relay.\n");
                    close_session(proxy, index, "unsupported ProQuake cheat-free handshake");
                    return;
                }
                if (!accept_upstream_connection(proxy, connection, data, (size_t)received)) {
                    reject_client(proxy, &connection->client,
                                  "FAQProxy received a malformed server acceptance.\n");
                    close_session(proxy, index, "malformed upstream acceptance");
                    return;
                }
                connection = &proxy->sessions[index];
                continue;
            }
            if (view.command == NQ_CCREP_REJECT) {
                if ((size_t)received > sizeof(connection->cached_accept)) {
                    close_session(proxy, index, "oversized upstream rejection");
                    return;
                }
                if (rate_limiter_allow(&proxy->reject_limiter, FAQPROXY_REJECT_RATE,
                                       FAQPROXY_REJECT_BURST))
                    (void)send_datagram(proxy->listen_fd, data, (size_t)received,
                                        &connection->client);
                close_session(proxy, index, "upstream rejected connection");
                return;
            }
            app_log(proxy, 1, "session %lu: ignored unexpected control reply 0x%02x\n",
                    connection->id, view.command);
            continue;
        }
        if (connection->state == SESSION_CONNECTING) {
            app_log(proxy, 1, "session %lu: ignored non-control data before acceptance\n",
                    connection->id);
            continue;
        }

        if (connection->state == SESSION_QUERY) {
            uint8_t rewritten[FAQPROXY_MAX_CONTROL_PACKET + sizeof(proxy->cfg.advertise)];
            const uint8_t *reply = data;
            size_t reply_length = (size_t)received;

            if (reply_length > FAQPROXY_MAX_CONTROL_PACKET ||
                !nq_parse_packet(data, reply_length, &view) || !view.control ||
                view.command != expected_query_reply(connection->query_command)) {
                app_log(proxy, 1, "session %lu: ignored malformed control reply\n",
                        connection->id);
                continue;
            }
            if (view.command == NQ_CCREP_SERVER_INFO) {
                reply_length = rewrite_server_info(proxy, rewritten, sizeof(rewritten), data,
                                                   reply_length);
                if (!reply_length) {
                    close_session(proxy, index, "malformed server-info reply");
                    return;
                }
                reply = rewritten;
            }
            (void)send_datagram(proxy->listen_fd, reply, reply_length, &connection->client);
            if (connection->query_command != NQ_CCREQ_RCON) {
                close_session(proxy, index, "control query complete");
                return;
            }
            continue;
        }

        if (connection->state == SESSION_ESTABLISHED) {
            if (!nq_parse_packet(data, (size_t)received, &view) || view.control) {
                app_log(proxy, 1, "session %lu: ignored malformed connected server packet\n",
                        connection->id);
                continue;
            }
            if (!connection->client_confirmed) {
                if (connection->unconfirmed_packets_from_server >=
                        FAQPROXY_UNCONFIRMED_MAX_PACKETS ||
                    (uint64_t)received > FAQPROXY_UNCONFIRMED_MAX_BYTES -
                                             connection->unconfirmed_bytes_from_server) {
                    close_session(proxy, index, "unconfirmed relay limit");
                    return;
                }
                connection->unconfirmed_packets_from_server++;
                connection->unconfirmed_bytes_from_server += (uint64_t)received;
            }
        }

        if (!send_datagram(proxy->listen_fd, data, (size_t)received, &connection->client)) {
            app_log(proxy, 1, "session %lu: server datagram send failed: %s\n", connection->id,
                    socket_error_string());
            continue;
        }
        if (connection->state == SESSION_ESTABLISHED)
            inspect_connected_packet(proxy, connection, true, data, (size_t)received);
        app_log(proxy, 2, "session %lu: server -> client %ld bytes\n", connection->id,
                (long)received);
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
        else if (!connection->client_confirmed) {
            limit = FAQPROXY_CONFIRM_TIMEOUT_MS;
            if (idle_limit && idle_limit < limit)
                limit = idle_limit;
        }
        else
            limit = idle_limit;
        if (limit && now - connection->last_client_activity_ms > limit)
            close_session(proxy, i, "idle timeout");
    }
}

static int poll_sockets(proxy_pollfd *descriptors, proxy_nfds count, int timeout)
{
#ifdef _WIN32
    return WSAPoll(descriptors, count, timeout);
#else
    return poll(descriptors, count, timeout);
#endif
}

static int run_proxy(app *proxy)
{
    proxy_pollfd descriptors[FAQPROXY_MAX_SESSIONS + 1];
    int session_map[FAQPROXY_MAX_SESSIONS + 1];

    while (!stop_requested) {
        proxy_nfds count = 1;
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

        status = poll_sockets(descriptors, count, FAQPROXY_POLL_MS);
        if (status < 0) {
            if (socket_interrupted())
                continue;
            fprintf(stderr, "poll failed: %s\n", socket_error_string());
            return 1;
        }
        if (descriptors[0].revents & POLLIN)
            drain_client_socket(proxy);
        if (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "listen socket failed\n");
            return 1;
        }
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
            "  -a, --advertise ADDRESS[:PORT] address placed in server-browser replies\n"
            "  -r, --record-dir DIRECTORY   record each connection as a NetQuake .dem\n"
            "  -m, --max-clients NUMBER     simultaneous sessions, 1-64 (default 32)\n"
            "  -t, --timeout SECONDS        client-idle timeout; 0 disables (default 120)\n"
            "      --connect-rate NUMBER    new connections per second; 0 disables limit "
            "(default 16)\n"
            "      --query-rate NUMBER      control queries per second; 0 disables limit "
            "(default 32)\n"
            "      --max-demo-mib NUMBER    per-demo size limit; 0 disables (default 1024)\n"
            "      --allow-player-info      relay queries that may expose player addresses\n"
            "      --allow-rcon             relay plaintext RCON queries (unsafe)\n"
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

    if (!text || !*text)
        return false;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || end == text || *end || value < minimum || value > maximum)
        return false;
    *result = (unsigned int)value;
    return true;
}

typedef enum command_line_result {
    COMMAND_LINE_RUN = 0,
    COMMAND_LINE_EXIT_OK,
    COMMAND_LINE_EXIT_ERROR
} command_line_result;

static bool match_long_option(const char *argument, const char *name, const char **inline_value)
{
    size_t length = strlen(name);

    if (strncmp(argument, name, length) != 0)
        return false;
    if (argument[length] == 0) {
        *inline_value = NULL;
        return true;
    }
    if (argument[length] != '=')
        return false;
    *inline_value = argument + length + 1;
    return true;
}

static command_line_result parse_command_line(app *proxy, int argc, char **argv,
                                              const char **listen_argument,
                                              const char **advertise_argument,
                                              const char **server_argument)
{
    int index = 1;
    unsigned int parsed_value;

    while (index < argc) {
        const char *argument = argv[index];
        const char *value = NULL;
        int option = 0;

        if (strcmp(argument, "--") == 0) {
            ++index;
            break;
        }
        if (argument[0] != '-' || argument[1] == 0)
            break;
        if (argument[1] == '-') {
            if (strcmp(argument, "--help") == 0)
                option = 'h';
            else if (strcmp(argument, "--version") == 0)
                option = 1000;
            else if (strcmp(argument, "--verbose") == 0)
                option = 'v';
            else if (strcmp(argument, "--allow-player-info") == 0)
                option = 1001;
            else if (strcmp(argument, "--allow-rcon") == 0)
                option = 1002;
            else if (match_long_option(argument, "--listen", &value))
                option = 'l';
            else if (match_long_option(argument, "--advertise", &value))
                option = 'a';
            else if (match_long_option(argument, "--record-dir", &value))
                option = 'r';
            else if (match_long_option(argument, "--max-clients", &value))
                option = 'm';
            else if (match_long_option(argument, "--timeout", &value))
                option = 't';
            else if (match_long_option(argument, "--max-demo-mib", &value))
                option = 1003;
            else if (match_long_option(argument, "--query-rate", &value))
                option = 1004;
            else if (match_long_option(argument, "--connect-rate", &value))
                option = 1005;
        } else if (argument[1] == 'l' || argument[1] == 'a' || argument[1] == 'r' ||
                   argument[1] == 'm' || argument[1] == 't') {
            option = (unsigned char)argument[1];
            if (argument[2])
                value = argument + 2;
        } else if (argument[1] == 'v') {
            const char *character = argument + 1;

            while (*character == 'v') {
                if (proxy->cfg.verbose < 2)
                    ++proxy->cfg.verbose;
                ++character;
            }
            if (*character)
                option = 0;
            else {
                ++index;
                continue;
            }
        } else if (strcmp(argument, "-h") == 0) {
            option = 'h';
        }

        if (!option) {
            fprintf(stderr, "Unknown option: %s\n", argument);
            print_usage(stderr, argv[0]);
            return COMMAND_LINE_EXIT_ERROR;
        }
        if ((option == 'l' || option == 'a' || option == 'r' || option == 'm' || option == 't' ||
             option == 1003 || option == 1004 || option == 1005) &&
            !value) {
            if (++index >= argc) {
                fprintf(stderr, "Option %s requires a value\n", argument);
                print_usage(stderr, argv[0]);
                return COMMAND_LINE_EXIT_ERROR;
            }
            value = argv[index];
        }

        switch (option) {
        case 'l':
            *listen_argument = value;
            break;
        case 'a':
            *advertise_argument = value;
            break;
        case 'r':
            if (!*value) {
                fprintf(stderr, "--record-dir must not be empty\n");
                return COMMAND_LINE_EXIT_ERROR;
            }
            if (strlen(value) >= sizeof(proxy->cfg.record_dir)) {
                fprintf(stderr, "Record directory path is too long\n");
                return COMMAND_LINE_EXIT_ERROR;
            }
            memcpy(proxy->cfg.record_dir, value, strlen(value) + 1);
            break;
        case 'm':
            if (!parse_unsigned(value, 1, FAQPROXY_MAX_SESSIONS, &parsed_value)) {
                fprintf(stderr, "--max-clients must be between 1 and %d\n", FAQPROXY_MAX_SESSIONS);
                return COMMAND_LINE_EXIT_ERROR;
            }
            proxy->cfg.max_sessions = (int)parsed_value;
            break;
        case 't':
            if (!parse_unsigned(value, 0, 86400, &parsed_value)) {
                fprintf(stderr, "--timeout must be between 0 and 86400 seconds\n");
                return COMMAND_LINE_EXIT_ERROR;
            }
            proxy->cfg.idle_timeout_seconds = parsed_value;
            break;
        case 'v':
            if (proxy->cfg.verbose < 2)
                ++proxy->cfg.verbose;
            break;
        case 1001:
            proxy->cfg.allow_player_info = true;
            break;
        case 1002:
            proxy->cfg.allow_rcon = true;
            break;
        case 1003:
            if (!parse_unsigned(value, 0, 1048576, &parsed_value)) {
                fprintf(stderr, "--max-demo-mib must be between 0 and 1048576\n");
                return COMMAND_LINE_EXIT_ERROR;
            }
            proxy->cfg.max_demo_bytes = (uint64_t)parsed_value * UINT64_C(1024) * UINT64_C(1024);
            break;
        case 1004:
            if (!parse_unsigned(value, 0, 10000, &parsed_value)) {
                fprintf(stderr, "--query-rate must be between 0 and 10000\n");
                return COMMAND_LINE_EXIT_ERROR;
            }
            proxy->cfg.query_rate = parsed_value;
            break;
        case 1005:
            if (!parse_unsigned(value, 0, 10000, &parsed_value)) {
                fprintf(stderr, "--connect-rate must be between 0 and 10000\n");
                return COMMAND_LINE_EXIT_ERROR;
            }
            proxy->cfg.connect_rate = parsed_value;
            break;
        case 1000:
            printf("faqproxy %s\n", FAQPROXY_VERSION);
            return COMMAND_LINE_EXIT_OK;
        case 'h':
            print_usage(stdout, argv[0]);
            return COMMAND_LINE_EXIT_OK;
        default:
            return COMMAND_LINE_EXIT_ERROR;
        }
        ++index;
    }

    if (index + 1 != argc) {
        print_usage(stderr, argv[0]);
        return COMMAND_LINE_EXIT_ERROR;
    }
    *server_argument = argv[index];
    return COMMAND_LINE_RUN;
}

int main(int argc, char **argv)
{
    app *proxy;
    const char *listen_argument = "0.0.0.0:26000";
    const char *advertise_argument = NULL;
    const char *server_argument = NULL;
    command_line_result command_line;
    int exit_status;
    int i;

    if (!initialize_network())
        return 1;
    proxy = calloc(1, sizeof(*proxy));
    if (!proxy) {
        fprintf(stderr, "Out of memory\n");
        return 1;
    }
    proxy->listen_fd = PROXY_INVALID_SOCKET;
    proxy->cfg.max_sessions = 32;
    proxy->cfg.idle_timeout_seconds = 120;
    proxy->cfg.connect_rate = FAQPROXY_DEFAULT_CONNECT_RATE;
    proxy->cfg.query_rate = FAQPROXY_DEFAULT_QUERY_RATE;
    proxy->cfg.max_demo_bytes =
        (uint64_t)FAQPROXY_DEFAULT_MAX_DEMO_MIB * UINT64_C(1024) * UINT64_C(1024);
    command_line = parse_command_line(proxy, argc, argv, &listen_argument, &advertise_argument,
                                      &server_argument);
    if (command_line != COMMAND_LINE_RUN) {
        free(proxy);
        return command_line == COMMAND_LINE_EXIT_OK ? 0 : 2;
    }
    if (!resolve_endpoint(listen_argument, "0.0.0.0", NQ_DEFAULT_PORT, true,
                          &proxy->cfg.listen_address, proxy->cfg.listen_text,
                          sizeof(proxy->cfg.listen_text)) ||
        !resolve_endpoint(server_argument, NULL, NQ_DEFAULT_PORT, false, &proxy->cfg.target_address,
                          proxy->cfg.target_text, sizeof(proxy->cfg.target_text))) {
        free(proxy);
        return 2;
    }
    if (advertise_argument &&
        !normalize_advertise(advertise_argument, ntohs(proxy->cfg.listen_address.sin_port),
                             proxy->cfg.advertise, sizeof(proxy->cfg.advertise))) {
        fprintf(stderr, "Invalid --advertise address (use HOST[:PORT])\n");
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
        proxy->sessions[i].upstream_fd = PROXY_INVALID_SOCKET;
    proxy->listen_fd = open_listen_socket(&proxy->cfg.listen_address, &proxy->listen_port);
    if (proxy->listen_fd == PROXY_INVALID_SOCKET) {
        fprintf(stderr, "Cannot listen on %s: %s\n", proxy->cfg.listen_text, socket_error_string());
        free(proxy);
        return 1;
    }
    proxy->cfg.listen_address.sin_port = htons(proxy->listen_port);
    format_address(&proxy->cfg.listen_address, proxy->cfg.listen_text,
                   sizeof(proxy->cfg.listen_text));
    if (advertise_argument)
        (void)normalize_advertise(advertise_argument, proxy->listen_port, proxy->cfg.advertise,
                                  sizeof(proxy->cfg.advertise));
    if (!advertise_argument &&
        proxy->cfg.listen_address.sin_addr.s_addr != htonl(INADDR_ANY))
        format_address(&proxy->cfg.listen_address, proxy->cfg.advertise,
                       sizeof(proxy->cfg.advertise));
    if (!install_signal_handlers()) {
        fprintf(stderr, "Cannot install signal handlers: %s\n", strerror(errno));
        close_socket(proxy->listen_fd);
        free(proxy);
        return 1;
    }

    fprintf(stderr,
            "faqproxy %s: NetQuake protocols 15/666/999\n"
            "listening on %s, forwarding to %s, max clients %d\n",
            FAQPROXY_VERSION, proxy->cfg.listen_text, proxy->cfg.target_text,
            proxy->cfg.max_sessions);
    if (proxy->cfg.record_dir[0]) {
        if (proxy->cfg.max_demo_bytes)
            fprintf(stderr, "recording demos in %s (limit %llu MiB each)\n",
                    proxy->cfg.record_dir,
                    (unsigned long long)(proxy->cfg.max_demo_bytes / UINT64_C(1024) /
                                         UINT64_C(1024)));
        else
            fprintf(stderr, "recording demos in %s (no size limit)\n", proxy->cfg.record_dir);
    }
    if (proxy->cfg.advertise[0])
        fprintf(stderr, "server-browser address: %s\n", proxy->cfg.advertise);
    else
        fprintf(stderr, "server-info queries disabled; use --advertise on a wildcard listener\n");
    if (proxy->cfg.connect_rate)
        fprintf(stderr, "connection rate: %u/second, burst %u\n", proxy->cfg.connect_rate,
                proxy->cfg.connect_rate * 2);
    else
        fprintf(stderr, "warning: connection rate limit disabled\n");
    if (proxy->cfg.query_rate)
        fprintf(stderr, "control-query rate: %u/second, burst %u\n", proxy->cfg.query_rate,
                proxy->cfg.query_rate * 2);
    else
        fprintf(stderr, "warning: control-query rate limit disabled\n");
    if (proxy->cfg.allow_player_info)
        fprintf(stderr, "warning: player-info query relay enabled\n");
    if (proxy->cfg.allow_rcon)
        fprintf(stderr, "warning: plaintext RCON query relay enabled\n");
#ifndef _WIN32
    if (geteuid() == 0)
        fprintf(stderr, "warning: running as root; use a dedicated unprivileged account\n");
#endif

    exit_status = run_proxy(proxy);
    for (i = 0; i < proxy->cfg.max_sessions; ++i)
        close_session(proxy, i, "proxy shutdown");
    close_socket(proxy->listen_fd);
    fprintf(stderr, "faqproxy stopped\n");
    free(proxy);
    return exit_status;
}
