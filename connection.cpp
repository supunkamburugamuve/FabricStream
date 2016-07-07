/*
 * connection.cpp
 *
 *  Created on: Jul 6, 2016
 *      Author: supun
 */
#include <cstdio>

#include "utils.h"
#include "connection.h"

Connection::Connection(RDMAOptions *opts) {
	this->options = opts;
	this->info = NULL;
	this->info_pep = NULL;
	this->info_hints = NULL;

	this->txcq = NULL;
	this->rxcq = NULL;
	this->txcntr = NULL;
	this->rxcntr = NULL;
	this->fabric = NULL;
	this->eq = NULL;
	this->domain = NULL;
	this->pep = NULL;
	this->ep = NULL;
	this->alias_ep = NULL;
	this->av = NULL;
	this->mr = NULL;
	this->no_mr = {};

	this->rx_fd = -1;
	this->tx_fd = -1;

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
	this->tx_ctx = {};
	this->rx_ctx = {};

	this->tx_seq = 0;
	this->rx_seq = 0;
	this->tx_cq_cntr = 0;
	this->rx_cq_cntr = 0;

	this->ft_skip_mr = 0;

	// initialize this attribute, search weather this is correct
	this->eq_attr.wait_obj = FI_WAIT_UNSPEC;

	// get the information
	// rdma_utils_get_info(this->options, hints, &this->info);

	this->cq_attr.wait_obj = FI_WAIT_NONE;
	this->cntr_attr.events = FI_CNTR_EVENTS_COMP;
	this->cntr_attr.wait_obj = FI_WAIT_NONE;

	this->av_attr.type = FI_AV_MAP;
	this->av_attr.count = 1;

	this->remote_fi_addr = FI_ADDR_UNSPEC;

	this->timeout = -1;
}

int Connection::AllocateActiveRes(struct fi_info *hints, struct fi_info *fi) {
	int ret;
	printf("Allocate recv\n");
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


Connection::~Connection() {

}

