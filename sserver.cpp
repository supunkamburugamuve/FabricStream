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
#include "connection.h"

#include "sserver.h"

SServer::SServer(RDMAOptions *opts, fi_info *hints) {
	this->options = opts;
	this->info_hints = hints;
	this->pep = NULL;
	this->info_pep = NULL;
	this->eq = NULL;
	this->fabric = NULL;
	this->eq_attr = {};
	// initialize this attribute, search weather this is correct
    this->eq_attr.wait_obj = FI_WAIT_UNSPEC;
    this->con = NULL;
}

void SServer::Free() {
	if (this->options) {
		options->Free();
	}
	if (this->info_pep) {
		fi_freeinfo(this->info_pep);
		this->info_pep = NULL;
	}
	if (this->info_hints) {
		fi_freeinfo(this->info_hints);
		this->info_hints = NULL;
	}
}

SServer::~SServer() {

}

/**
 * Initialize the server
 */
int SServer::Start(void) {
	int ret;
	printf("Start server\n");
	// info for passive end-point
	ret = rdma_utils_get_info(this->options, this->info_hints, &this->info_pep);
	if (ret) {
		return ret;
	}

	// create the fabric for passive end-point
	ret = fi_fabric(this->info_pep->fabric_attr, &fabric, NULL);
	if (ret) {
		printf("fi_fabric %d\n", ret);
		return ret;
	}

	// open the event queue for passive end-point
	ret = fi_eq_open(this->fabric, &this->eq_attr, &this->eq, NULL);
	if (ret) {
		printf("fi_eq_open %d\n", ret);
		return ret;
	}

	// allocates a passive end-point
	ret = fi_passive_ep(this->fabric, this->info_pep, &this->pep, NULL);
	if (ret) {
		printf("fi_passive_ep %d\n", ret);
		return ret;
	}

	// bind the passive end-point to the event queue
	ret = fi_pep_bind(this->pep, &eq->fid, 0);
	if (ret) {
		printf("fi_pep_bind %d\n", ret);
		return ret;
	}

	// start listen for incoming connections
	ret = fi_listen(this->pep);
	if (ret) {
		printf("fi_listen %d\n", ret);
		return ret;
	}

	return 0;
}

int SServer::Connect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;
	struct fid_ep *ep;
	struct fid_domain *domain;
	Connection *con;

	// read the events for incoming messages
	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		printf("fi_eq_sread listen\n");
		return (int) rd;
	}

	// this is the correct fi_info associated with active end-point
	if (event != FI_CONNREQ) {
		fprintf(stderr, "Unexpected CM event %d\n", event);
		ret = -FI_EOTHER;
		goto err;
	}

	ret = fi_domain(this->fabric, entry.info, &domain, NULL);
	if (ret) {
		printf("fi_domain %d\n", ret);
		goto err;
	}

	// create the connection
	con = new Connection(this->options, this->info_hints,
			entry.info, this->fabric, domain, this->eq);
	// allocate the queues and counters
	ret = con->AllocateActiveResources();
	if (ret) {
		goto err;
	}

	// create the end point for this connection
	ret = fi_endpoint(domain, entry.info, &ep, NULL);
	if (ret) {
		printf("fi_endpoint %d\n", ret);
		goto err;
	}

	// initialize the EP
	ret = con->InitEp(ep, this->eq);
	if (ret) {
		goto err;
	}

	// accept the incoming connection
	ret = fi_accept(ep, NULL, 0);
	if (ret) {
		printf("fi_accept %d\n", ret);
		goto err;
	}

	// read the confirmation
	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		printf("fi_eq_sread accept %d\n", (int)rd);
		ret = (int) rd;
		goto err;
	}

	if (event != FI_CONNECTED || entry.fid != &ep->fid) {
		fprintf(stderr, "Unexpected CM event %d fid %p (ep %p)\n",
			event, entry.fid, ep);
		ret = -FI_EOTHER;
		goto err;
	}

	printf("Connection established\n");
	this->con = con;
	return 0;
err:
	fi_reject(pep, entry.info->handle, NULL, 0);
	return ret;
}

int SServer::ExchangeKeys(struct fi_rma_iov *peer_iov) {
	if (this->con) {
		return con->ExchangeKeysServer(peer_iov);
	}
	return EXIT_FAILURE;
}

int SServer::sync(void) {
	if (this->con) {
		int ret;
		ret = this->con->RX(1);
		if (ret) {
			return ret;
		}
		ret = this->con->TX(1);
		return ret;
	}
	return EXIT_FAILURE;
}

ssize_t SServer::RMA(enum rdma_rma_opcodes op, size_t size, fi_rma_iov *remote) {
	if (this->con) {
		return con->RMA(op, size, remote);
	}
	return EXIT_FAILURE;
}

int SServer::Finalize(void) {
	if (this->con) {
		return con->Finalize();
	}
	return EXIT_FAILURE;
}



