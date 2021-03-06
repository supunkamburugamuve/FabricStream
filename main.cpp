#include <iostream>
#include <unistd.h>
#include <cstdio>
# include <cstring>

#include "utils.h"
#include "server.h"
#include "client.h"
#include "sclient.h"
#include "sserver.h"

using namespace std;

#define FT_PRINT_OPTS_USAGE(opt, desc) fprintf(stderr, " %-20s %s\n", opt, desc);

static struct fi_rma_iov remote;

struct test_size_param {
	int size;
	int enable_flags;
};

#define FT_DEFAULT_SIZE		(1 << 0)

struct test_size_param test_size[] = {
	{ 1 <<  1, 0 }, { (1 <<  1) + (1 <<  0), 0 },
	{ 1 <<  2, 0 }, { (1 <<  2) + (1 <<  1), 0 },
	{ 1 <<  3, 0 }, { (1 <<  3) + (1 <<  2), 0 },
	{ 1 <<  4, 0 }, { (1 <<  4) + (1 <<  3), 0 },
	{ 1 <<  5, 0 }, { (1 <<  5) + (1 <<  4), 0 },
	{ 1 <<  6, FT_DEFAULT_SIZE }, { (1 <<  6) + (1 <<  5), 0 },
	{ 1 <<  7, 0 }, { (1 <<  7) + (1 <<  6), 0 },
	{ 1 <<  8, FT_DEFAULT_SIZE }, { (1 <<  8) + (1 <<  7), 0 },
	{ 1 <<  9, 0 }, { (1 <<  9) + (1 <<  8), 0 },
	{ 1 << 10, FT_DEFAULT_SIZE }, { (1 << 10) + (1 <<  9), 0 },
	{ 1 << 11, 0 }, { (1 << 11) + (1 << 10), 0 },
	{ 1 << 12, FT_DEFAULT_SIZE }, { (1 << 12) + (1 << 11), 0 },
	{ 1 << 13, 0 }, { (1 << 13) + (1 << 12), 0 },
	{ 1 << 14, 0 }, { (1 << 14) + (1 << 13), 0 },
	{ 1 << 15, 0 }, { (1 << 15) + (1 << 14), 0 },
	{ 1 << 16, FT_DEFAULT_SIZE }, { (1 << 16) + (1 << 15), 0 },
	{ 1 << 17, 0 }, { (1 << 17) + (1 << 16), 0 },
	{ 1 << 18, 0 }, { (1 << 18) + (1 << 17), 0 },
	{ 1 << 19, 0 }, { (1 << 19) + (1 << 18), 0 },
	{ 1 << 20, FT_DEFAULT_SIZE }, { (1 << 20) + (1 << 19), 0 },
	{ 1 << 21, 0 }, { (1 << 21) + (1 << 20), 0 },
	{ 1 << 22, 0 }, { (1 << 22) + (1 << 21), 0 },
	{ 1 << 23, 0 },
};

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

int rma(int argc, char **argv) {
	int op;
	int ret = 0;
	RDMAOptions options;
	options.transfer_size = 100;
	options.rma_op = FT_RMA_WRITE;
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
	hints->mode = FI_LOCAL_MR | FI_RX_CQ_DATA;

	if (options.dst_addr) {
		SClient client(&options, hints);
		client.Connect();
		ret = client.ExchangeKeys();
		if (ret) {
			printf("Failed to exchange %d\n", ret);
		} else {
			printf("Exchanged keys\n");
		}

		ret = client.sync();
		if (ret) {
			printf("Failed to sync\n");
		} else {
			printf("synced\n");
		}

		for (int i = 0; i < 10000; i++) {
			options.transfer_size = test_size[0].size;
			ret = client.RMA(options.rma_op, options.transfer_size);
			if (ret) {
				printf("Failed to RMA \n");
			}
		}
		printf("Done rma\n");
		ret = client.sync();
		if (ret) {
			printf("Failed second sync");
		}
		ret = client.Finalize();
		if (ret) {
			printf("Failed Finalize");
		}
	} else {
		SServer server(&options, hints);
		server.Start();
		server.Connect();
		ret = server.ExchangeKeys();
		if (ret) {
			printf("Failed to exchange %d\n", ret);
		} else {
			printf("Exchanged keys\n");
		}
		ret = server.sync();
		if (ret) {
			printf("Failed to sync\n");
		} else {
			printf("synced\n");
		}
		for (int i = 0; i < 10000; i++) {
			options.transfer_size = test_size[0].size;
			ret = server.RMA(options.rma_op, options.transfer_size);
			if (ret) {
				printf("Failed to RMA \n");
			}
		}
				printf("Done rma\n");
		ret = server.sync();
		if (ret) {
			printf("Failed second sync");
		}
		ret = server.Finalize();
		if (ret) {
			printf("Failed Finalize");
		}
	}

	return 0;
}

int send_recv(int argc, char **argv) {
	int op;
	int ret = 0;
	RDMAOptions options;
	options.transfer_size = 100;
	options.buf_size = 100000;
	options.no_buffers = 10;
	options.rma_op = FT_RMA_WRITE;
	Connection *con;
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
	hints->mode = FI_LOCAL_MR | FI_RX_CQ_DATA;

	if (options.dst_addr) {
		SClient client(&options, hints);
		client.Connect();
		ret = client.ExchangeKeys();
		if (ret) {
			printf("Failed to exchange %d\n", ret);
		} else {
			printf("Exchanged keys\n");
		}

		ret = client.sync();
		if (ret) {
			printf("Failed to sync\n");
		} else {
			printf("synced\n");
		}
		con = client.GetConnection();
		int values[1000];
		uint8_t send_buf[4000];
        // create an integer array with size 1000
		for (int i = 0; i < 1000; i++) {
			values[i] = i;
		}
		memcpy((uint8_t *)send_buf, (uint8_t *)values, 4000);
		// now write this to buffer
		for (int i = 0; i < 1000; i++) {
			con->WriteData(send_buf, 4000);
		}

		ret = client.sync();
		if (ret) {
			printf("Failed second sync");
		}
		ret = client.Finalize();
		if (ret) {
			printf("Failed Finalize");
		}
	} else {
		SServer server(&options, hints);
		server.Start();
		server.Connect();
		ret = server.ExchangeKeys();
		if (ret) {
			printf("Failed to exchange %d\n", ret);
		} else {
			printf("Exchanged keys\n");
		}
		ret = server.sync();
		if (ret) {
			printf("Failed to sync\n");
		} else {
			printf("synced\n");
		}

//		int values[1000];
//		uint8_t recv_buf[4000];
//		// create an integer array with size 1000
//		for (int i = 0; i < 1000; i++) {
//			values[i] = i;
//		}
//		memcpy((uint8_t *)send_buf, (uint8_t *)values, 4000);
//		// now write this to buffer
		con = server.GetConnection();
		for (int i = 0; i < 1000; i++) {
			con->receive();
			// con->WriteBuffers();
		}

		ret = server.sync();
		if (ret) {
			printf("Failed second sync");
		}
		ret = server.Finalize();
		if (ret) {
			printf("Failed Finalize");
		}
	}

	return 0;
}

int main(int argc, char **argv) {
	send_recv(argc, argv);
}

int main2(int argc, char **argv) {
	int op;
	int ret = 0;
	RDMAOptions options;
	options.transfer_size = 100;
	options.rma_op = FT_RMA_WRITE;
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
	hints->mode = FI_LOCAL_MR | FI_RX_CQ_DATA;

	if (options.dst_addr) {
		RDMACLient client(&options, hints);
		client.ClientConnect();
		ret = client.ExchangeKeys(&remote);
		if (ret) {
			printf("Failed to exchange %d\n", ret);
		} else {
			printf("Exchanged keys\n");
		}
		ret = client.sync();
		if (ret) {
			printf("Failed to sync\n");
		} else {
			printf("synced\n");
		}

		for (int i = 0; i < 10000; i++) {
			options.transfer_size = test_size[0].size;
			ret = client.RMA(options.rma_op, options.transfer_size, &remote);
			if (ret) {
				printf("Failed to RMA \n");
			}
		}
                printf("Done rma\n");
		ret = client.sync();
		if (ret) {
			printf("Failed second sync");
		}
		ret = client.Finalize();
		if (ret) {
			printf("Failed Finalize");
		}
	} else {
		RDMAServer server(&options, hints);
		server.StartServer();
		server.ServerConnect();
		ret = server.ExchangeKeys(&remote);
		if (ret) {
			printf("Failed to exchange %d\n", ret);
		} else {
			printf("Exchanged keys\n");
		}
		ret = server.sync();
		if (ret) {
			printf("Failed to sync\n");
		} else {
            printf("synced\n");
        }
		for (int i = 0; i < 10000; i++) {
			options.transfer_size = test_size[0].size;
			ret = server.RMA(options.rma_op, options.transfer_size, &remote);
			if (ret) {
				printf("Failed to RMA \n");
			}
		}
                printf("Done rma\n");
		ret = server.sync();
		if (ret) {
			printf("Failed second sync");
		}
		ret = server.Finalize();
		if (ret) {
			printf("Failed Finalize");
		}
	}

    return 0;
}
