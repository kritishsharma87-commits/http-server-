#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define MAX_EVENTS 64
#define BUFFER_SIZE 4096
#define WEB_ROOT "./public"

/* Global flag for graceful shutdown */
static volatile sig_atomic_t keep_running = 1;

/* Structure for storing an HTTP request */
typedef struct {
    char method[16];
    char path[256];
    char version[16];
} http_request_t;

/* ---------------------------------------------------------
   Signal Handler
   --------------------------------------------------------- */
static void handle_signal(int signal_number)
{
    (void)signal_number;
    keep_running = 0;
}

/* ---------------------------------------------------------
   Set File Descriptor to Non-Blocking Mode
   --------------------------------------------------------- */
static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;
}

/* ---------------------------------------------------------
   Get MIME Type
   --------------------------------------------------------- */
static const char *get_mime_type(const char *path)
{
    const char *extension = strrchr(path, '.');

    if (extension == NULL) {
        return "application/octet-stream";
    }

    if (strcmp(extension, ".html") == 0 ||
        strcmp(extension, ".htm") == 0) {
        return "text/html";
    }

    if (strcmp(extension, ".css") == 0) {
        return "text/css";
    }

    if (strcmp(extension, ".js") == 0) {
        return "application/javascript";
    }

    if (strcmp(extension, ".png") == 0) {
        return "image/png";
    }

    if (strcmp(extension, ".jpg") == 0 ||
        strcmp(extension, ".jpeg") == 0) {
        return "image/jpeg";
    }

    if (strcmp(extension, ".gif") == 0) {
        return "image/gif";
    }

    if (strcmp(extension, ".svg") == 0) {
        return "image/svg+xml";
    }

    if (strcmp(extension, ".json") == 0) {
        return "application/json";
    }

    if (strcmp(extension, ".txt") == 0) {
        return "text/plain";
    }

    return "application/octet-stream";
}

/* ---------------------------------------------------------
   Send All Data
   --------------------------------------------------------- */
static int send_all(int fd, const void *buffer, size_t length)
{
    const char *data = (const char *)buffer;
    size_t total_sent = 0;

    while (total_sent < length) {
        ssize_t sent = send(
            fd,
            data + total_sent,
            length - total_sent,
            MSG_NOSIGNAL
        );

        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        if (sent == 0) {
            return -1;
        }

        total_sent += (size_t)sent;
    }

    return 0;
}

/* ---------------------------------------------------------
   Send HTTP Response
   --------------------------------------------------------- */
static void send_response(
    int client_fd,
    int status_code,
    const char *status_text,
    const char *content_type,
    const void *body,
    size_t body_length
)
{
    char header[BUFFER_SIZE];

    int header_length = snprintf(
        header,
        sizeof(header),

        "HTTP/1.1 %d %s\r\n"
        "Server: C-Epoll-Server/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",

        status_code,
        status_text,
        content_type,
        body_length
    );

    if (header_length < 0 ||
        (size_t)header_length >= sizeof(header)) {
        return;
    }

    send_all(client_fd, header, (size_t)header_length);

    if (body != NULL && body_length > 0) {
        send_all(client_fd, body, body_length);
    }
}

/* ---------------------------------------------------------
   Parse HTTP Request
   --------------------------------------------------------- */
static int parse_http_request(
    const char *raw_request,
    http_request_t *request
)
{
    if (raw_request == NULL || request == NULL) {
        return -1;
    }

    int result = sscanf(
        raw_request,
        "%15s %255s %15s",
        request->method,
        request->path,
        request->version
    );

    if (result != 3) {
        return -1;
    }

    return 0;
}

/* ---------------------------------------------------------
   Check for Directory Traversal
   --------------------------------------------------------- */
static int is_safe_path(const char *path)
{
    if (path == NULL) {
        return 0;
    }

    /*
       Prevent ../ and encoded-style traversal attempts
       in this simple server.
    */
    if (strstr(path, "..") != NULL) {
        return 0;
    }

    if (strstr(path, "\\") != NULL) {
        return 0;
    }

    return 1;
}

/* ---------------------------------------------------------
   Handle Client Request
   --------------------------------------------------------- */
static void handle_client(int client_fd)
{
    char buffer[BUFFER_SIZE];

    ssize_t bytes_read = recv(
        client_fd,
        buffer,
        sizeof(buffer) - 1,
        0
    );

    if (bytes_read < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv");
        }

        return;
    }

    if (bytes_read == 0) {
        return;
    }

    buffer[bytes_read] = '\0';

    /* Parse HTTP request */
    http_request_t request;

    if (parse_http_request(buffer, &request) != 0) {
        const char *body = "<h1>400 Bad Request</h1>";

        send_response(
            client_fd,
            400,
            "Bad Request",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Only GET is supported */
    if (strcmp(request.method, "GET") != 0) {
        const char *body = "<h1>405 Method Not Allowed</h1>";

        send_response(
            client_fd,
            405,
            "Method Not Allowed",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Only HTTP/1.0 and HTTP/1.1 are accepted */
    if (strcmp(request.version, "HTTP/1.0") != 0 &&
        strcmp(request.version, "HTTP/1.1") != 0) {

        const char *body = "<h1>505 HTTP Version Not Supported</h1>";

        send_response(
            client_fd,
            505,
            "HTTP Version Not Supported",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Security check */
    if (!is_safe_path(request.path)) {
        const char *body = "<h1>403 Forbidden</h1>";

        send_response(
            client_fd,
            403,
            "Forbidden",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Remove query string */
    char clean_path[256];

    strncpy(
        clean_path,
        request.path,
        sizeof(clean_path) - 1
    );

    clean_path[sizeof(clean_path) - 1] = '\0';

    char *query_string = strchr(clean_path, '?');

    if (query_string != NULL) {
        *query_string = '\0';
    }

    /* Determine requested file */
    char full_path[512];

    if (strcmp(clean_path, "/") == 0) {

        snprintf(
            full_path,
            sizeof(full_path),
            "%s/index.html",
            WEB_ROOT
        );

    } else {

        snprintf(
            full_path,
            sizeof(full_path),
            "%s%s",
            WEB_ROOT,
            clean_path
        );
    }

    /* Get file information */
    struct stat file_stat;

    if (stat(full_path, &file_stat) == -1) {

        const char *body = "<h1>404 Not Found</h1>";

        send_response(
            client_fd,
            404,
            "Not Found",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Do not serve directories */
    if (S_ISDIR(file_stat.st_mode)) {

        const char *body = "<h1>403 Forbidden</h1>";

        send_response(
            client_fd,
            403,
            "Forbidden",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Check that it is a regular file */
    if (!S_ISREG(file_stat.st_mode)) {

        const char *body = "<h1>403 Forbidden</h1>";

        send_response(
            client_fd,
            403,
            "Forbidden",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Open requested file */
    FILE *file = fopen(full_path, "rb");

    if (file == NULL) {

        perror("fopen");

        const char *body = "<h1>500 Internal Server Error</h1>";

        send_response(
            client_fd,
            500,
            "Internal Server Error",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Empty file */
    if (file_stat.st_size == 0) {

        fclose(file);

        send_response(
            client_fd,
            200,
            "OK",
            get_mime_type(full_path),
            NULL,
            0
        );

        return;
    }

    /* Allocate memory for file */
    size_t file_size = (size_t)file_stat.st_size;

    char *file_buffer = malloc(file_size);

    if (file_buffer == NULL) {

        fclose(file);

        const char *body = "<h1>500 Internal Server Error</h1>";

        send_response(
            client_fd,
            500,
            "Internal Server Error",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Read file */
    size_t bytes_read_from_file = fread(
        file_buffer,
        1,
        file_size,
        file
    );

    fclose(file);

    if (bytes_read_from_file != file_size) {

        free(file_buffer);

        const char *body = "<h1>500 Internal Server Error</h1>";

        send_response(
            client_fd,
            500,
            "Internal Server Error",
            "text/html",
            body,
            strlen(body)
        );

        return;
    }

    /* Send file to client */
    send_response(
        client_fd,
        200,
        "OK",
        get_mime_type(full_path),
        file_buffer,
        file_size
    );

    free(file_buffer);
}

/* ---------------------------------------------------------
   Main Function
   --------------------------------------------------------- */
int main(void)
{
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    /* Configure SIGINT and SIGTERM */
    struct sigaction signal_action;

    memset(&signal_action, 0, sizeof(signal_action));

    signal_action.sa_handler = handle_signal;

    sigemptyset(&signal_action.sa_mask);

    signal_action.sa_flags = 0;

    if (sigaction(SIGINT, &signal_action, NULL) == -1) {
        perror("sigaction SIGINT");
        return EXIT_FAILURE;
    }

    if (sigaction(SIGTERM, &signal_action, NULL) == -1) {
        perror("sigaction SIGTERM");
        return EXIT_FAILURE;
    }

    /* -----------------------------------------------------
       Create Server Socket
       ----------------------------------------------------- */

    int server_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (server_fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    /* Allow reuse of address */
    int socket_option = 1;

    if (setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &socket_option,
            sizeof(socket_option)) == -1) {

        perror("setsockopt");

        close(server_fd);

        return EXIT_FAILURE;
    }

    /* -----------------------------------------------------
       Configure Server Address
       ----------------------------------------------------- */

    struct sockaddr_in server_address;

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family = AF_INET;

    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    server_address.sin_port = htons(PORT);

    /* -----------------------------------------------------
       Bind
       ----------------------------------------------------- */

    if (bind(
            server_fd,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) == -1) {

        perror("bind");

        close(server_fd);

        return EXIT_FAILURE;
    }

    /* -----------------------------------------------------
       Listen
       ----------------------------------------------------- */

    if (listen(server_fd, SOMAXCONN) == -1) {

        perror("listen");

        close(server_fd);

        return EXIT_FAILURE;
    }

    /* Set server socket to non-blocking */
    if (set_nonblocking(server_fd) == -1) {

        perror("set_nonblocking");

        close(server_fd);

        return EXIT_FAILURE;
    }

    /* -----------------------------------------------------
       Create epoll instance
       ----------------------------------------------------- */

    int epoll_fd = epoll_create1(0);

    if (epoll_fd == -1) {

        perror("epoll_create1");

        close(server_fd);

        return EXIT_FAILURE;
    }

    /* Event structure */
    struct epoll_event server_event;

    memset(
        &server_event,
        0,
        sizeof(server_event)
    );

    server_event.events = EPOLLIN;

    server_event.data.fd = server_fd;

    /* Add server socket to epoll */
    if (epoll_ctl(
            epoll_fd,
            EPOLL_CTL_ADD,
            server_fd,
            &server_event) == -1) {

        perror("epoll_ctl");

        close(epoll_fd);
        close(server_fd);

        return EXIT_FAILURE;
    }

    printf("=====================================\n");
    printf("       C HTTP SERVER STARTED\n");
    printf("=====================================\n");
    printf("Server: http://localhost:%d\n", PORT);
    printf("Web root: %s\n", WEB_ROOT);
    printf("Press Ctrl+C to stop the server.\n");
    printf("=====================================\n\n");

    /* -----------------------------------------------------
       Main Event Loop
       ----------------------------------------------------- */

    struct epoll_event events[MAX_EVENTS];

    while (keep_running) {

        int number_of_events = epoll_wait(
            epoll_fd,
            events,
            MAX_EVENTS,
            1000
        );

        if (number_of_events == -1) {

            if (errno == EINTR) {
                continue;
            }

            perror("epoll_wait");

            break;
        }

        /* Process events */
        for (int i = 0; i < number_of_events; i++) {

            int current_fd = events[i].data.fd;

            /* -------------------------------------------------
               New Client Connection
               ------------------------------------------------- */

            if (current_fd == server_fd) {

                while (1) {

                    struct sockaddr_in client_address;

                    socklen_t client_address_length =
                        sizeof(client_address);

                    int client_fd = accept(
                        server_fd,
                        (struct sockaddr *)&client_address,
                        &client_address_length
                    );

                    if (client_fd == -1) {

                        if (errno == EAGAIN ||
                            errno == EWOULDBLOCK) {
                            break;
                        }

                        if (errno == EINTR) {
                            continue;
                        }

                        perror("accept");

                        break;
                    }

                    /* Set client socket to non-blocking */
                    if (set_nonblocking(client_fd) == -1) {

                        perror("set_nonblocking client");

                        close(client_fd);

                        continue;
                    }

                    /* Add client to epoll */
                    struct epoll_event client_event;

                    memset(
                        &client_event,
                        0,
                        sizeof(client_event)
                    );

                    client_event.events =
                        EPOLLIN | EPOLLET;

                    client_event.data.fd = client_fd;

                    if (epoll_ctl(
                            epoll_fd,
                            EPOLL_CTL_ADD,
                            client_fd,
                            &client_event) == -1) {

                        perror("epoll_ctl client");

                        close(client_fd);

                        continue;
                    }

                    printf(
                        "Client connected: %s:%d\n",
                        inet_ntoa(client_address.sin_addr),
                        ntohs(client_address.sin_port)
                    );
                }
            }

            /* -------------------------------------------------
               Client Request
               ------------------------------------------------- */

            else {

                int client_fd = current_fd;

                /* Check for errors */
                if (events[i].events &
                    (EPOLLERR | EPOLLHUP)) {

                    epoll_ctl(
                        epoll_fd,
                        EPOLL_CTL_DEL,
                        client_fd,
                        NULL
                    );

                    close(client_fd);

                    continue;
                }

                /* Handle request */
                handle_client(client_fd);

                /* Remove client from epoll */
                epoll_ctl(
                    epoll_fd,
                    EPOLL_CTL_DEL,
                    client_fd,
                    NULL
                );

                /* Close connection */
                close(client_fd);
            }
        }
    }

    /* ---------------------------------------------------------
       Shutdown
       --------------------------------------------------------- */

    printf("\nShutting down server...\n");

    close(epoll_fd);

    close(server_fd);

    printf("Server stopped successfully.\n");

    return EXIT_SUCCESS;
}
