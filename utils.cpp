#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "rdma_fabric.h"
#include "utils.h"

char default_port[8] = "9228";

RDMAOptions::RDMAOptions() {
	this->dst_addr = NULL;
	this->dst_port = NULL;
	this->src_addr = NULL;
	this->src_port = NULL;
	this->av_name = NULL;
	this->options = -1;
}

int rdma_utils_set_rma_caps(struct fi_info *fi) {
	fi->caps |= FI_REMOTE_READ;
	if (fi->mode & FI_LOCAL_MR)
		fi->caps |= FI_READ;

	fi->caps |= FI_REMOTE_WRITE;
	if (fi->mode & FI_LOCAL_MR)
		fi->caps |= FI_WRITE;
	return 0;
}


static void rdma_utils_cq_set_wait_attr(RDMAOptions *opts, struct fid_wait *waitset, struct fi_cq_attr *cq_attr) {
	switch (opts->comp_method) {
	case FT_COMP_SREAD:
		cq_attr->wait_obj = FI_WAIT_UNSPEC;
		cq_attr->wait_cond = FI_CQ_COND_NONE;
		break;
	case FT_COMP_WAITSET:
		cq_attr->wait_obj = FI_WAIT_SET;
		cq_attr->wait_cond = FI_CQ_COND_NONE;
		cq_attr->wait_set = waitset;
		break;
	case FT_COMP_WAIT_FD:
		cq_attr->wait_obj = FI_WAIT_FD;
		cq_attr->wait_cond = FI_CQ_COND_NONE;
		break;
	default:
		cq_attr->wait_obj = FI_WAIT_NONE;
		break;
	}
}

static void rdma_utils_cntr_set_wait_attr(RDMAOptions *opts, struct fid_wait *waitset, struct fi_cntr_attr *cntr_attr) {
	switch (opts->comp_method) {
	case FT_COMP_SREAD:
		cntr_attr->wait_obj = FI_WAIT_UNSPEC;
		break;
	case FT_COMP_WAITSET:
		cntr_attr->wait_obj = FI_WAIT_SET;
		break;
	case FT_COMP_WAIT_FD:
		cntr_attr->wait_obj = FI_WAIT_FD;
		break;
	default:
		cntr_attr->wait_obj = FI_WAIT_NONE;
		break;
	}
}

static int rdma_utils_dupaddr(void **dst_addr, size_t *dst_addrlen,
		void *src_addr, size_t src_addrlen) {
	*dst_addr = malloc(src_addrlen);
	*dst_addrlen = src_addrlen;
	memcpy(*dst_addr, src_addr, src_addrlen);
	return 0;
}

/**
 * Get the address according to the format supported by the device
 */
static int rdm_utils_getaddr(char *node, char *service,
			struct fi_info *hints, uint64_t flags) {
	int ret;
	struct fi_info *fi;

	if (!node && !service) {
		if (flags & FI_SOURCE) {
			hints->src_addr = NULL;
			hints->src_addrlen = 0;
		} else {
			hints->dest_addr = NULL;
			hints->dest_addrlen = 0;
		}
		return 0;
	}

	printf("Get info with options node=%s service=%s flags=%d\n", node, service, flags);

	ret = fi_getinfo(RDMA_FIVERSION, node, service, flags, hints, &fi);
	if (ret) {
		return ret;
	}
	hints->addr_format = fi->addr_format;

	if (flags & FI_SOURCE) {
		ret = rdma_utils_dupaddr(&hints->src_addr, &hints->src_addrlen,
				fi->src_addr, fi->src_addrlen);
	} else {
		ret = rdma_utils_dupaddr(&hints->dest_addr, &hints->dest_addrlen,
				fi->dest_addr, fi->dest_addrlen);
	}

	fi_freeinfo(fi);
	return ret;
}

int rdma_utils_read_addr_opts(char **node, char **service, struct fi_info *hints,
		uint64_t *flags, RDMAOptions *opts) {
	int ret;

	if (opts->dst_addr) {
		if (!opts->dst_port) {
			opts->dst_port = default_port;
		}

		ret = rdm_utils_getaddr(opts->src_addr, opts->src_port, hints, FI_SOURCE);
		if (ret) {
			return ret;
		}
		*node = opts->dst_addr;
		*service = opts->dst_port;
	} else {
		if (!opts->src_port) {
			opts->src_port = default_port;
		}
		*node = opts->src_addr;
		*service = opts->src_port;
		*flags = FI_PROV_ATTR_ONLY;
	}

	return 0;
}

int rdma_utils_get_info(RDMAOptions *options, struct fi_info *hints, struct fi_info **info) {
	int ret;
	char *fi_str;
	char *node, *service;
	uint64_t flags = 0;
	// read the parameters from the options
	rdma_utils_read_addr_opts(&node, &service, hints, &flags, options);

	// default to RDM
	if (!hints->ep_attr->type) {
		hints->ep_attr->type = FI_EP_RDM;
	}

	hints->domain_attr->mr_mode = FI_MR_BASIC;
	hints->ep_attr->type = FI_EP_RDM;
	hints->caps = FI_MSG | FI_RMA | FI_RMA_EVENT;
	hints->mode = FI_CONTEXT | FI_LOCAL_MR | FI_RX_CQ_DATA;

	// now lets retrieve the available network services
	// according to hints
	ret = fi_getinfo(RDMA_FIVERSION, node, service, flags, hints, info);
	if (*info) {
		fi_info *next = *info;
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
	return 0;
}




