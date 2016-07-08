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

#include "rdma_fabric.h"
#include "server.h"
#include "utils.h"
#include "sclient.h"
#include "connection.h"

SClient::SClient(RDMAOptions *opts, fi_info *hints) {
	this->info = NULL;
	this->info_hints = hints;
	this->options = opts;
	this->eq = NULL;
	this->fabric = NULL;
	this->eq_attr = {};
	this->eq_attr.wait_obj = FI_WAIT_UNSPEC;
}

SClient::~SClient() {
}

int SClient::Connect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;
	struct fid_ep *ep;
	struct fid_domain *domain;
	Connection *con;

	printf("Client connect \n");
	ret = rdma_utils_get_info(this->options, this->info_hints, &this->info);
	if (ret)
		return ret;

	ret = fi_fabric(this->info->fabric_attr, &this->fabric, NULL);
	if (ret) {
		printf("fi_fabric %d\n", ret);
		return ret;
	}

	ret = fi_eq_open(this->fabric, &this->eq_attr, &this->eq, NULL);
	if (ret) {
		printf("fi_eq_open %d\n", ret);
		return ret;
	}

	ret = fi_domain(this->fabric, this->info, &domain, NULL);
	if (ret) {
		printf("fi_domain %d\n", ret);
		return ret;
	}

	// create the connection
	con = new Connection(this->options, this->info_hints,
			this->info, this->fabric, domain, this->eq);

	// allocate the resources
	ret = con->AllocateActiveResources();
	if (ret) {
		return ret;
	}

	// create the end point for this connection
	ret = fi_endpoint(domain, entry.info, &ep, NULL);
	if (ret) {
		printf("fi_endpoint %d\n", ret);
		return ret;
	}

	// initialize the endpoint
	ret = con->InitEp(ep, this->eq);
	if (ret) {
		return ret;
	}

	ret = fi_connect(ep, this->info->dest_addr, NULL, 0);
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