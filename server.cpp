#include <iostream>
#include <cstdio>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "rdma_fabric.h"
#include "server.h"
#include "utils.h"

int RDMAServer::OpenFabric(void) {
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

int RDMAServer::StartServer(void) {
	int ret;

	ret = fi_eq_open(this->fabric, &this->eq_attr, &this->eq, NULL);
	if (ret) {
		printf("fi_eq_open %d\n", ret);
		return ret;
	}

	ret = fi_passive_ep(this->fabric, this->info_hints, &this->pep, NULL);
	if (ret) {
		printf("fi_passive_ep %d\n", ret);
		return ret;
	}

	ret = fi_pep_bind(pep, &eq->fid, 0);
	if (ret) {
		printf("fi_pep_bind %d\n", ret);
		return ret;
	}

	ret = fi_listen(pep);
	if (ret) {
		printf("fi_listen %d\n", ret);
		return ret;
	}

	return 0;
}

int ft_set_rma_caps(struct fi_info *fi, enum ft_rma_opcodes rma_op) {
	switch (rma_op) {
	case FT_RMA_READ:
		fi->caps |= FI_REMOTE_READ;
		if (fi->mode & FI_LOCAL_MR)
			fi->caps |= FI_READ;
		break;
	case FT_RMA_WRITE:
	case FT_RMA_WRITEDATA:
		fi->caps |= FI_REMOTE_WRITE;
		if (fi->mode & FI_LOCAL_MR)
			fi->caps |= FI_WRITE;
		break;
	default:
		FT_ERR("Invalid rma op type\n");
		return -FI_EINVAL;
	}
	return 0;
}

int RDMAServer::AllocateReceive(struct fi_info *fi) {
	int ret;
	if (this->info_hints->caps & FI_RMA) {
		ret = ft_set_rma_caps(fi, opts.rma_op);
		if (ret)
			return ret;
	}

	ret = ft_alloc_msgs();
	if (ret)
		return ret;

	if (cq_attr.format == FI_CQ_FORMAT_UNSPEC) {
		if (fi->caps & FI_TAGGED)
			cq_attr.format = FI_CQ_FORMAT_TAGGED;
		else
			cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	}

	if (opts.options & FT_OPT_TX_CQ) {
		ft_cq_set_wait_attr();
		cq_attr.size = fi->tx_attr->size;
		ret = fi_cq_open(domain, &cq_attr, &txcq, &txcq);
		if (ret) {
			FT_PRINTERR("fi_cq_open", ret);
			return ret;
		}
	}

	if (opts.options & FT_OPT_TX_CNTR) {
		ft_cntr_set_wait_attr();
		ret = fi_cntr_open(domain, &cntr_attr, &txcntr, &txcntr);
		if (ret) {
			FT_PRINTERR("fi_cntr_open", ret);
			return ret;
		}
	}

	if (opts.options & FT_OPT_RX_CQ) {
		ft_cq_set_wait_attr();
		cq_attr.size = fi->rx_attr->size;
		ret = fi_cq_open(domain, &cq_attr, &rxcq, &rxcq);
		if (ret) {
			FT_PRINTERR("fi_cq_open", ret);
			return ret;
		}
	}

	if (opts.options & FT_OPT_RX_CNTR) {
		ft_cntr_set_wait_attr();
		ret = fi_cntr_open(domain, &cntr_attr, &rxcntr, &rxcntr);
		if (ret) {
			FT_PRINTERR("fi_cntr_open", ret);
			return ret;
		}
	}

	if (fi->ep_attr->type == FI_EP_RDM || fi->ep_attr->type == FI_EP_DGRAM) {
		if (fi->domain_attr->av_type != FI_AV_UNSPEC)
			av_attr.type = fi->domain_attr->av_type;

		if (opts.av_name) {
			av_attr.name = opts.av_name;
		}
		ret = fi_av_open(domain, &av_attr, &av, NULL);
		if (ret) {
			FT_PRINTERR("fi_av_open", ret);
			return ret;
		}
	}

	ret = fi_endpoint(domain, fi, &ep, NULL);
	if (ret) {
		FT_PRINTERR("fi_endpoint", ret);
		return ret;
	}

	return 0;
}

int RDMAServer::ServerConnect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	rd = fi_eq_sread(this->eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		FT_PROCESS_EQ_ERR(rd, eq, "fi_eq_sread", "listen");
		return (int) rd;
	}

	fi = entry.info;
	if (event != FI_CONNREQ) {
		fprintf(stderr, "Unexpected CM event %d\n", event);
		ret = -FI_EOTHER;
		goto err;
	}

	ret = ft_alloc_active_res(fi);
	if (ret)
		goto err;

	ret = ft_init_ep();
	if (ret)
		goto err;

	ret = fi_accept(ep, NULL, 0);
	if (ret) {
		FT_PRINTERR("fi_accept", ret);
		goto err;
	}

	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		FT_PROCESS_EQ_ERR(rd, eq, "fi_eq_sread", "accept");
		ret = (int) rd;
		goto err;
	}

	if (event != FI_CONNECTED || entry.fid != &ep->fid) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ep);
		ret = -FI_EOTHER;
		goto err;
	}

	return 0;

err:
	fi_reject(pep, fi->handle, NULL, 0);
	return ret;
}


/**
 * Initialize the server with options
 */
RDMAServer::RDMAServer(RDMAOptions *opts, struct fi_info *hints) {
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

	OpenFabric();
}


