#include <iostream>
#include <cstdio>

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

int RDMACLient::OpenFabric(void) {
	fi_info *f;
	int ret;
	char *name = "IB-0x80fe";
	this->info->fabric_attr->name = this->options->fname;
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

int RDMACLient::AllocateActiveRes(struct fi_info *hints, struct fi_info *fi) {
	int ret;

	if (hints->caps & FI_RMA) {
		ret = rdma_utils_set_rma_caps(fi);
		if (ret)
			return ret;
	}

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

	if (fi->ep_attr->type == FI_EP_MSG)
		FT_EP_BIND(ep, eq, 0);
	FT_EP_BIND(ep, av, 0);
	FT_EP_BIND(ep, txcq, FI_TRANSMIT);
	FT_EP_BIND(ep, rxcq, FI_RECV);

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
	flags = !rxcq ? FI_RECV : 0;
	if (hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ)) {
		flags |= hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ);
	} else if (hints->caps & FI_RMA) {
		flags |= FI_REMOTE_WRITE | FI_REMOTE_READ;
	}
	FT_EP_BIND(ep, rxcntr, flags);

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

int RDMACLient::ClientConnect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

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
		printf("fi_eq_sread", "connect");
		ret = (int) rd;
		return ret;
	}

	if (event != FI_CONNECTED || entry.fid != &ep->fid) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ep);
		ret = -FI_EOTHER;
		return ret;
	}

	return 0;
}

RDMACLient::RDMACLient(RDMAOptions *opts, fi_info *hints) {
	int ret;
	char *node, *service;
	uint64_t flags = 0;

	char *fi_str;
	this->options = opts;

	// allocate the hints
	this->info_hints = hints;

	// initialize this attribute, search weather this is correct
	this->eq_attr.wait_obj = FI_WAIT_UNSPEC;

	// read the parameters from the options
	rdma_utils_read_addr_opts(&node, &service, this->info_hints, &flags, opts);

	// default to RDM
	if (!hints->ep_attr->type) {
		hints->ep_attr->type = FI_EP_RDM;
	}

	this->info_hints->domain_attr->mr_mode = FI_MR_BASIC;
	this->info_hints->ep_attr->type = FI_EP_RDM;
	this->info_hints->caps = FI_MSG | FI_RMA | FI_RMA_EVENT;
	this->info_hints->mode = FI_CONTEXT | FI_LOCAL_MR | FI_RX_CQ_DATA;

	// now lets retrieve the available network services
	// according to hints
	ret = fi_getinfo(RDMA_FIVERSION, node, service, flags, this->info_hints, &this->info);
	if (this->info) {
		fi_info *next = this->info;
		while (next) {
			fi_fabric_attr *attr = next->fabric_attr;
			printf("fabric attr name=%s prov_name=%s\n", attr->name, attr->prov_name);
			fi_str = fi_tostr(next, FI_TYPE_INFO);
			std::cout << "FI" << fi_str << std::endl;
			next = next->next;
		}
	} else {
		// throw exception, we cannot proceed
	}

	ClientConnect();
}
