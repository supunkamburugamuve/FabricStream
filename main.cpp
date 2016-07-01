#include <iostream>
#include <unistd.h>
#include <cstdio>
# include <cstring>

#include "utils.h"
#include "server.h"
#include "client.h"

using namespace std;

#define FT_PRINT_OPTS_USAGE(opt, desc) fprintf(stderr, " %-20s %s\n", opt, desc);

static struct fi_rma_iov remote;

void rdma_parseinfo(int op, char *optarg, struct fi_info *hints) {
	switch (op) {
	case 'n':
		if (!hints->domain_attr) {
			hints->domain_attr = (struct fi_domain_attr	*)malloc(sizeof *(hints->domain_attr));
			if (!hints->domain_attr) {
				exit(EXIT_FAILURE);
			}
		}
		hints->domain_attr->name = strdup(optarg);
		break;
	case 'f':
		if (!hints->fabric_attr) {
			hints->fabric_attr = (struct fi_fabric_attr	*	)malloc(sizeof *(hints->fabric_attr));
			if (!hints->fabric_attr) {
				exit(EXIT_FAILURE);
			}
		}
		printf("prov_name: %s\n", optarg);
		hints->fabric_attr->prov_name = strdup(optarg);
		break;
	case 'e':
		if (!strncasecmp("msg", optarg, 3)) {
			hints->ep_attr->type = FI_EP_MSG;
		}
		if (!strncasecmp("rdm", optarg, 3)) {
			hints->ep_attr->type = FI_EP_RDM;
		}
		if (!strncasecmp("dgram", optarg, 5)) {
			hints->ep_attr->type = FI_EP_DGRAM;
		}
		break;
	default:
		break;
	}
}

void rdma_parse_addr_opts(int op, char *optarg, RDMAOptions *opts) {
	switch (op) {
	case 's':
		printf("source addr: %s\n", optarg);
		opts->src_addr = optarg;
		break;
	case 'b':
		printf("source port: %s\n", optarg);
		opts->src_port = optarg;
		break;
	case 'p':
		printf("dst port: %s\n", optarg);
		opts->dst_port = optarg;
		break;
	case 'r':
		printf("fname: %s\n", optarg);
		opts->fname = strdup(optarg);
		break;
	default:
		/* let getopt handle unknown opts*/
		break;
	}
}

int main(int argc, char **argv) {
	int op;
	RDMAOptions options;
	struct fi_info *hints = fi_allocinfo();
    // parse the options
    while ((op = getopt(argc, argv, "ho:" ADDR_OPTS INFO_OPTS)) != -1) {
		switch (op) {
		default:
			rdma_parseinfo(op, optarg, hints);
			rdma_parse_addr_opts(op, optarg, &options);
			break;
		case '?':
		case 'h':
			fprintf(stderr, "Help not implemented\n");
			return 0;
		}
	}

    if (optind < argc) {
    	options.dst_addr = argv[optind];
    	printf("dst addr: %s\n", options.dst_addr);
    }

    hints->ep_attr->type = FI_EP_MSG;
	hints->caps = FI_MSG | FI_RMA;
	hints->mode = FI_CONTEXT | FI_LOCAL_MR | FI_RX_CQ_DATA;

	if (options.dst_addr) {
		RDMACLient client(&options, hints);
		client.ClientConnect();
		client.ExchangeKeys(&remote);
	} else {
		RDMAServer server(&options, hints);
		server.StartServer();
		server.ServerConnect();
		server.ExchangeKeys(&remote);
	}

    return 0;
}
