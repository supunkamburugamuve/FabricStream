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

	// bind the passive end-point to event queue
	ret = fi_pep_bind(this->pep, &eq->fid, 0);
	if (ret) {
		printf("fi_pep_bind %d\n", ret);
		return ret;
	}

	// listen for incoming connections
	ret = fi_listen(this->pep);
	if (ret) {
		printf("fi_listen %d\n", ret);
		return ret;
	}

	return 0;
}


int RDMAServer::ServerConnect(void) {
	struct fi_eq_cm_entry entry;
	uint32_t event;
	ssize_t rd;
	int ret;

	// read the events for incoming messages
	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		printf("fi_eq_sread listen\n");
		return (int) rd;
	}

	// this is the correct fi_info associated with active endpoint
	this->info = entry.info;
	if (event != FI_CONNREQ) {
		fprintf(stderr, "Unexpected CM event %d\n", event);
		ret = -FI_EOTHER;
		goto err;
	}

	ret = fi_domain(this->fabric, this->info, &this->domain, NULL);
	if (ret) {
		printf("fi_domain %d\n", ret);
		goto err;
	}

	ret = rdma_alloc_active_res(fi);
	if (ret) {
		goto err;
	}

	ret = rdma_init_ep();
	if (ret) {
		goto err;
	}

	ret = fi_accept(ep, NULL, 0);
	if (ret) {
		printf("fi_accept %d\n", ret);
		goto err;
	}

	rd = fi_eq_sread(eq, &event, &entry, sizeof entry, -1, 0);
	if (rd != sizeof entry) {
		printf("fi_eq_sread accept %d\n");
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
	fi_reject(pep, info->handle, NULL, 0);
	return ret;
}

/**
 * Initialize the server with options
 */
RDMAServer::RDMAServer(RDMAOptions *opts, struct fi_info *hints) {
    char *fi_str;
	this->options = opts;

	// allocate the hints
	this->info_hints = hints;

	// initialize this attribute, search weather this is correct
	this->eq_attr.wait_obj = FI_WAIT_UNSPEC;

	// get the information
	rdma_utils_get_info(this->options, hints, &this->info);

	this->cq_attr.wait_obj = FI_WAIT_NONE;

	// now open fabric
	OpenFabric();
}


