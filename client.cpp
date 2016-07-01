#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstdlib>
#include <cstring>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "client.h"
#include "rdma_fabric.h"
#include "utils.h"

int RDMACLient::ShutDown(void) {
	return 0;
}

int RDMACLient::OpenFabric2(void) {
	fi_info *f;
	int ret;
	printf("Fabric name: %s, Prov Name %s\n", this->info->fabric_attr->name, this->info->fabric_attr->prov_name);
	ret = fi_fabric(this->info->fabric_attr, &this->fabric, NULL);
	if (ret) {
		std::cout << "Failed to create fabric:" << ret << std::endl;
		return ret;
	}
	std::cout << "Opened fabric:" << std::endl;
	ret = fi_eq_open(this->fabric, &this->eq_attr, &this->eq, NULL);
	if (ret) {
		std::cout << "Failed to open eq:" << ret << std::endl;
		return ret;
	}
	std::cout << "Opened eq:" << std::endl;

	for (f = this->info; f; f = f->next) {
		ret = fi_domain(this->fabric, this->info, &this->domain, NULL);
		if (ret) {
		  printf("Could not init domain using provider %s: %s",
			   f->fabric_attr->prov_name,
			   fi_strerror(-ret));
		}
		else {
		  printf("Created FI domain on %s : %s : %s",
			   f->fabric_attr->prov_name,
			   f->fabric_attr->name,
			   fi_tostr(&f->ep_attr->type, FI_TYPE_EP_TYPE));
		  break;
		}
	}

	std::cout << "Opened domain:" << std::endl;
	return 0;
}

/*
 * Include FI_MSG_PREFIX space in the allocated buffer, and ensure that the
 * buffer is large enough for a control message used to exchange addressing
 * data.
 */
int RDMACLient::AllocMsgs(void) {
	int ret;
	long alignment = 1;
	RDMAOptions *opts = this->options;
	/* TODO: support multi-recv tests */
	if (info->rx_attr->op_flags == FI_MULTI_RECV)
		return 0;

	tx_size = 10000;
	if (tx_size > info->ep_attr->max_msg_size)
		tx_size = info->ep_attr->max_msg_size;
	rx_size = tx_size + rdma_utils_rx_prefix_size(this->info);
	tx_size += rdma_utils_tx_prefix_size(this->info);

	buf_size = MAX(tx_size, FT_MAX_CTRL_MSG) + MAX(rx_size, FT_MAX_CTRL_MSG);

	if (opts->options & FT_OPT_ALIGN) {
		alignment = sysconf(_SC_PAGESIZE);
		if (alignment < 0)
			return -errno;
		buf_size += alignment;

		ret = posix_memalign(&buf, (size_t) alignment, buf_size);
		if (ret) {
			printf("posix_memalign %d\n", ret);
			return ret;
		}
	} else {
		buf = malloc(buf_size);
		if (!buf) {
			perror("malloc");
			return -FI_ENOMEM;
		}
	}
	memset(buf, 0, buf_size);
	rx_buf = buf;
	tx_buf = (char *) buf + MAX(rx_size, FT_MAX_CTRL_MSG);
	tx_buf = (void *) (((uintptr_t) tx_buf + alignment - 1) & ~(alignment - 1));

	remote_cq_data = rdma_utils_init_cq_data(info);

//	if (opts->window_size > 0) {
//		ctx_arr = calloc(opts->window_size, sizeof(struct fi_context));
//		if (!ctx_arr)
//			return -FI_ENOMEM;
//	}

	if (!ft_skip_mr && ((info->mode & FI_LOCAL_MR) ||
				(info->caps & (FI_RMA | FI_ATOMIC)))) {
		ret = fi_mr_reg(domain, buf, buf_size, rdma_utils_caps_to_mr_access(info->caps),
				0, FT_MR_KEY, 0, &mr, NULL);
		if (ret) {
			printf("fi_mr_reg %d\n", ret);
			return ret;
		}
	} else {
		mr = &no_mr;
	}

	return 0;
}

int RDMACLient::AllocateActiveRes(struct fi_info *hints, struct fi_info *fi) {
	int ret;
	printf("Allocate recv\n");
	if (hints->caps & FI_RMA) {
		ret = rdma_utils_set_rma_caps(fi);
		if (ret)
			return ret;
	}

	ret = AllocMsgs();
	if (ret)
		return ret;

	if (cq_attr.format == FI_CQ_FORMAT_UNSPEC) {
		if (fi->caps & FI_TAGGED)
			cq_attr.format = FI_CQ_FORMAT_TAGGED;
		else
			cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	}

	if (this->options->options & FT_OPT_TX_CQ) {
		rdma_utils_cq_set_wait_attr(this->options, this->waitset, &this->cq_attr);
		cq_attr.size = fi->tx_attr->size;
		ret = fi_cq_open(domain, &cq_attr, &txcq, &txcq);
		if (ret) {
			printf("fi_cq_open %d\n", ret);
			return ret;
		}
	}

	if (this->options->options & FT_OPT_TX_CNTR) {
		rdma_utils_cntr_set_wait_attr(this->options, this->waitset, &this->cntr_attr);
		ret = fi_cntr_open(domain, &cntr_attr, &txcntr, &txcntr);
		if (ret) {
			printf("fi_cntr_open %d\n", ret);
			return ret;
		}
	}

	if (this->options->options & FT_OPT_RX_CQ) {
		rdma_utils_cq_set_wait_attr(this->options, this->waitset, &this->cq_attr);
		cq_attr.size = fi->rx_attr->size;
		ret = fi_cq_open(domain, &cq_attr, &rxcq, &rxcq);
		if (ret) {
			printf("fi_cq_open %d\n", ret);
			return ret;
		}
	}

	if (this->options->options & FT_OPT_RX_CNTR) {
		rdma_utils_cntr_set_wait_attr(this->options, this->waitset, &this->cntr_attr);
		ret = fi_cntr_open(domain, &cntr_attr, &rxcntr, &rxcntr);
		if (ret) {
			printf("fi_cntr_open %d\n", ret);
			return ret;
		}
	}

	if (fi->ep_attr->type == FI_EP_RDM || fi->ep_attr->type == FI_EP_DGRAM) {
		if (fi->domain_attr->av_type != FI_AV_UNSPEC) {
			av_attr.type = fi->domain_attr->av_type;
		}

		if (this->options->av_name) {
			av_attr.name = this->options->av_name;
		}
		ret = fi_av_open(this->domain, &this->av_attr, &this->av, NULL);
		if (ret) {
			printf("fi_av_open %d\n", ret);
			return ret;
		}
	}

	ret = fi_endpoint(domain, fi, &ep, NULL);
	if (ret) {
		printf("fi_endpoint %d\n", ret);
		return ret;
	}

	return 0;
}

int RDMACLient::InitEp(struct fi_info *hints, struct fi_info *fi) {
	int flags, ret;

	printf("Init EP\n");
	if (fi->ep_attr->type == FI_EP_MSG)
		FT_EP_BIND(ep, eq, 0);
	//FT_EP_BIND(ep, av, 0);
	printf("av txcq rxcp bind 1\n");
	FT_EP_BIND(ep, txcq, FI_TRANSMIT);
	printf("av txcq rxcp bind 2\n");
	FT_EP_BIND(ep, rxcq, FI_RECV);
	printf("av txcq rxcp bind 3\n");

	printf("av txcq rxcp bind\n");
	ret = ft_get_cq_fd(this->options, txcq, &tx_fd);
	if (ret) {
		return ret;
	}

	ret = ft_get_cq_fd(this->options, rxcq, &rx_fd);
	if (ret) {
		return ret;
	}

	/* TODO: use control structure to select counter bindings explicitly */
	flags = !txcq ? FI_SEND : 0;
	if (hints->caps & (FI_WRITE | FI_READ)) {
		flags |= hints->caps & (FI_WRITE | FI_READ);
	} else if (hints->caps & FI_RMA) {
		flags |= FI_WRITE | FI_READ;
	}
	FT_EP_BIND(ep, txcntr, flags);
	printf("av txcq txcntr bind\n");
	flags = !rxcq ? FI_RECV : 0;
	if (hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ)) {
		flags |= hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ);
	} else if (hints->caps & FI_RMA) {
		flags |= FI_REMOTE_WRITE | FI_REMOTE_READ;
	}
	FT_EP_BIND(ep, rxcntr, flags);
	printf("av txcq rxcntr bind\n");
	ret = fi_enable(ep);
	if (ret) {
		printf("fi_enable %d\n", ret);
		return ret;
	}

	if (fi->rx_attr->op_flags != FI_MULTI_RECV) {
		/* Initial receive will get remote address for unconnected EPs */
		// ret = ft_post_rx(ep, MAX(rx_size, FT_MAX_CTRL_MSG), &rx_ctx);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

int RDMACLient::OpenFabric(void) {
	int ret;

	ret = fi_fabric(this->info->fabric_attr, &fabric, NULL);
	if (ret) {
		printf("fi_fabric %d\n", ret);
		return ret;
	}

	ret = fi_eq_open(fabric, &eq_attr, &eq, NULL);
	if (ret) {
		printf("fi_eq_open %d\n", ret);
		return ret;
	}

	ret = fi_domain(fabric, this->info, &domain, NULL);
	if (ret) {
		printf("fi_domain %d\n", ret);
		return ret;
	}

	return 0;
}

int RDMACLient::ClientConnect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	printf("Client connect \n");
	ret = rdma_utils_get_info(options, info_hints, &info);
	if (ret)
		return ret;

	ret = OpenFabric();
	if (ret)
		return ret;

	ret = AllocateActiveRes(info_hints, info);
	if (ret)
		return ret;

	ret = InitEp(this->info_hints, this->info);
	if (ret)
		return ret;

	ret = fi_connect(this->ep, this->info->dest_addr, NULL, 0);
	if (ret) {
		printf("fi_connect %d\n", ret);
		return ret;
	}

	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		printf("fi_eq_sread connect\n");
		ret = (int) rd;
		return ret;
	}

	if (event != FI_CONNECTED || entry.fid != &ep->fid) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ep);
		ret = -FI_EOTHER;
		return ret;
	}

	printf("COnnection established\n");

	return 0;
}

RDMACLient::RDMACLient(RDMAOptions *opts, fi_info *hints) {
	printf("RDMA Client\n");
	this->options = opts;
	this->info = NULL;
	this->info_pep = NULL;

	this->txcq = NULL;
	this->rxcq = NULL;
	this->txcntr = NULL;
	this->rxcntr = NULL;
	this->info_pep = NULL;
	this->fabric = NULL;
	this->eq = NULL;
	this->domain = NULL;
	this->pep = NULL;
	this->ep = NULL;
	this->alias_ep = NULL;
	this->av = NULL;
	this->mr = NULL;
	this->no_mr = {};

	this->tx_buf = NULL;
	this->buf = NULL;
	this->rx_buf = NULL;

	this->buf_size = 0;
	this->tx_size = 0;
	this->rx_size = 0;

	this->remote_cq_data = 0;
	this->waitset = NULL;

	// allocate the hints
	this->info_hints = hints;
	this->eq_attr = {};
	this->cq_attr = {};
	this->cntr_attr = {};
	this->av_attr = {};
	// initialize this attribute, search weather this is correct
	this->eq_attr.wait_obj = FI_WAIT_UNSPEC;

	// get the information
	// rdma_utils_get_info(this->options, hints, &this->info);

	this->cq_attr.wait_obj = FI_WAIT_NONE;
	this->cntr_attr.events = FI_CNTR_EVENTS_COMP;
	this->cntr_attr.wait_obj = FI_WAIT_NONE;

	this->av_attr.type = FI_AV_MAP;
	this->av_attr.count = 1;
}
