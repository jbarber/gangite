// For strdup+strndup
#define _XOPEN_SOURCE 700

// For asprintf
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include "expat.h"

#if defined(__amigaos__) && defined(__USE_INLINE__)
#include <proto/expat.h>
#endif

#ifdef XML_LARGE_SIZE
#if defined(XML_USE_MSC_EXTENSIONS) && _MSC_VER < 1400
#define XML_FMT_INT_MOD "I64"
#else
#define XML_FMT_INT_MOD "ll"
#endif
#else
#define XML_FMT_INT_MOD "l"
#endif

struct carbon {
    char *host;
    char *group;
    char *metric;
    char *value;
    char *timestamp;
    int carbon;
    int disconnected;
};

struct server {
    char *address;
    char *port;
};

static struct server gmond = { "127.0.0.1", "8649" };
static struct server carbond = { "127.0.0.1", "2023" };
static int poll = 10;
static int verbose = 0;

#define STREQ(x, y) strcmp(x, y) == 0
#define STRNEQ(x, y) strcmp(x, y) != 0

char * metric_path (struct carbon *d) {
    char *ret;

    if (d->group) {
        asprintf(&ret, "%s.%s.%s", d->host, d->group, d->metric);
    }
    else {
        asprintf(&ret, "%s.%s", d->host, d->metric);
    }
    return ret;
}

static void XMLCALL startElement(void *userData, const char *name, const char **atts) {
    size_t i = 0;
    struct carbon *data = (struct carbon *)userData;

    if (STREQ(name, "HOST")) {
        while (atts[i] != NULL) {
            if (STREQ(atts[i], "NAME")) {
                char *dot = strchr(atts[i+1], '.');
                if (dot == NULL) {
                    data->host = strdup(atts[i+1]);
                }
                else {
                    data->host = strndup(atts[i+1], dot - *(atts + i + 1));
                }
            }
            else if (STREQ(atts[i], "REPORTED")) {
                data->timestamp = strdup(atts[i+1]);
            }
            i += 2;
        }
    }
    else if (STREQ(name, "METRIC")) {
        const char *type, *name, *val;
        while (atts[i] != NULL) {
            if (STREQ(atts[i], "NAME")) {
                name = atts[i+1];
            }
            else if (STREQ(atts[i], "TYPE")) {
                type = atts[i+1];
            }
            else if (STREQ(atts[i], "VAL")) {
                val = atts[i+1];
            }
            i += 2;
        }
        if (STRNEQ(type, "string")) {
            char *n = strdup(name);
            char *p = NULL;
            while ((p = strchr(n, '.')) != NULL) {
                *p = '_';
            }
            data->metric = n;
            data->value = strdup(val);
        }
    }
    else if (STREQ(name, "EXTRA_ELEMENT")) {
        size_t group = 0;
        const char *val = NULL;
        while (atts[i] != NULL) {
            if (STREQ(atts[i], "NAME")) {
                if (STREQ(atts[i+1], "GROUP")) {
                    group = 1;
                }
            }
            else if (STREQ(atts[i], "VAL")) {
                val = atts[i+1];
            }
            i += 2;
        }

        if (group && val != NULL) {
            data->group = strdup(val);
        }
    }
}

static void XMLCALL endElement(void *userData, const char *name) {
    struct carbon *data = (struct carbon *)userData;
    if (STREQ(name, "METRIC")) {
        if (data->value) {
            char *msg;
            char *path = metric_path(data);
            int len = asprintf(&msg, "%s %s %s\n", path, data->value, data->timestamp);
            free(path);

            if (len < 0) {
                exit(EXIT_FAILURE);
            }
            else {
                if (send(data->carbon, msg, len, MSG_NOSIGNAL) < 0) {
                    data->disconnected = 1;
                }
                free(msg);
            }

            free(data->metric);

            free(data->value);
            data->value = NULL;
        }

        if (data->group != NULL) {
            free(data->group);
            data->group = NULL;
        }

    }
    else if (STREQ(name, "HOST")) {
        free(data->host);
        free(data->timestamp);
    }
}

int connect_server(const char *addr, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    int s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break; /* Success */
        }

        close(sfd);
    }

    if (rp == NULL) { /* No address succeeded */
        if (verbose)
            fprintf(stderr, "Could not connect to %s:%s\n", addr, port);
        return -1;
    }

    freeaddrinfo(result);
    return sfd;
}

XML_Parser create_parser (struct carbon *data) {
    XML_Parser parser = XML_ParserCreate(NULL);


    XML_SetUserData(parser, data);
    XML_SetElementHandler(parser, startElement, endElement);
}

void parse_args(int argc, char * const argv[]) {
    int opt = 0;
    char *c = NULL, *g = NULL;
    while ((opt = getopt(argc, argv, "hc:g:p:v")) != -1) {
        switch (opt) {
            case 'v':
                verbose++;
                break;
            case 'c':
                c = strdup(optarg);
                break;
            case 'g':
                g = strdup(optarg);
                break;
            case 'p':
                // FIXME: check for errors...
                poll = strtol(optarg, NULL, 10);
                break;
            case 'h':
            default:
                fprintf(stderr, "Usage: %s [-h] [-p poll] [-g gmond:port] [-c carbon:port]\n", basename(argv[0]));
                exit(EXIT_FAILURE);
        }
    }

    if (c != NULL) {
        char *p = strchr(c, ':');
        carbond.address = c;
        if (p != NULL) {
            *p = 0x0;
            carbond.port = p + 1;
        }
    }

    if (g != NULL) {
        char *p = strchr(g, ':');
        gmond.address = g;
        if (p != NULL) {
            *p = 0x0;
            gmond.port = p + 1;
        }
    }
}

int main(int argc, char **argv) {
    char buf[BUFSIZ];

    parse_args(argc, argv);

    struct carbon data = { NULL, NULL, NULL, NULL, NULL, 0, 0 };
    data.carbon = connect_server(carbond.address, carbond.port);

    while (1) {
        // FIXME: Probably it's not nessesary to continually connect/break
        // connections to the gmond server. Instead I think we can wait for
        // activity on the socket to indicate a new batch of statistics.
        XML_Parser parser = create_parser(&data);
        int gmond_s = connect_server(gmond.address, gmond.port);

        if (data.disconnected) {
            data.carbon = connect_server(carbond.address, carbond.port);
            data.disconnected = 0;
        }

        if (gmond_s >= 0 && data.carbon >= 0) {
            size_t done;
            // Read gmond data
            do {
                size_t len = recv(gmond_s, buf, BUFSIZ, 0);
                done = len == 0;
                if (XML_Parse(parser, buf, len, done) == XML_STATUS_ERROR) {
                    fprintf(stderr,
                            "%s at line %" XML_FMT_INT_MOD "u\n",
                            XML_ErrorString(XML_GetErrorCode(parser)),
                            XML_GetCurrentLineNumber(parser));
                    return EXIT_FAILURE;
                }
            } while (!done);

            close(gmond_s);
        }

        XML_ParserFree(parser);
        if (verbose) {
            fprintf(stderr, "Sleeping for %i seconds\n", poll);
        }
        sleep(poll);
    }

    return EXIT_SUCCESS;
}
