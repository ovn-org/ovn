/* Copyright (c) 2025 Crusoe Energy Systems LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/* OVS includes. */
#include "openvswitch/vlog.h"
#include "lib/command-line.h"
#include "lib/daemon.h"
#include "lib/dirs.h"
#include "lib/fatal-signal.h"
#include "lib/stream.h"
#include "lib/stream-ssl.h"
#include "lib/unixctl.h"

/* OVN includes. */
#include "lib/ovn-br-idl.h"
#include "lib/ovn-util.h"

VLOG_DEFINE_THIS_MODULE(main);

static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);


/* SSL/TLS options. */
static const char *ssl_private_key_file;
static const char *ssl_certificate_file;
static const char *ssl_ca_cert_file;

/* --unixctl-path: Path to use for unixctl server socket. */
static char *unixctl_path;

int
main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    return 0;
}

/* static functions. */
static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        OVN_DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {"unixctl", required_argument, NULL, 'u'},
        VLOG_LONG_OPTIONS,
        OVN_DAEMON_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {NULL, 0, NULL, 0}
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP15_VERSION, OFP15_VERSION);
            printf("OVN BR DB Schema %s\n", ovnbrrec_get_db_version());
            exit(EXIT_SUCCESS);

        case 'u':
            unixctl_path = optarg;
            break;

        VLOG_OPTION_HANDLERS
        OVN_DAEMON_OPTION_HANDLERS

        case 'p':
            ssl_private_key_file = optarg;
            break;

        case 'c':
            ssl_certificate_file = optarg;
            break;

        case 'C':
            ssl_ca_cert_file = optarg;
            break;

        case OPT_SSL_PROTOCOLS:
            stream_ssl_set_protocols(optarg);
            break;

        case OPT_SSL_CIPHERS:
            stream_ssl_set_ciphers(optarg);
            break;

        case OPT_SSL_CIPHERSUITES:
            stream_ssl_set_ciphersuites(optarg);
            break;

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            ovs_abort(0, "Invalid option.");
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;
}

static void
usage(void)
{
    printf("%s: OVN bridge controller\n"
           "usage %s [OPTIONS] [OVS-DATABASE]\n"
           "where OVS-DATABASE is a socket on which the OVS OVSDB server "
           "is listening.\n",
           program_name, program_name);
    stream_usage("OVS-DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -u, --unixctl=SOCKET    set control socket name\n"
           "  -n                      custom chassis name\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
