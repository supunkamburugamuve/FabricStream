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
	this->info_hints = fi_allocinfo();

	// initialize this attribute, search weather this is correct
	this->eq_attr.wait_obj = FI_WAIT_UNSPEC;

	// read the parameters from the options
	rdma_utils_read_addr_opts(&node, &service, this->info_hints, &flags, opts);

	// default to RDM
	if (!hints->ep_attr->type) {
		hints->ep_attr->type = FI_EP_RDM;
	}

	// now lets retrieve the available network services
	// according to hints
	ret = fi_getinfo(RDMA_FIVERSION, node, service, flags, info_hints, &this->info);
	if (this->info) {
		fi_info *next = this->info;
		while (next) {
			fi_str = fi_tostr(next, FI_TYPE_INFO);
            std::cout << "FI" << fi_str << std::endl;
            next = next->next;
		}
	} else {
		// throw exception, we cannot proceed
	}

	OpenFabric();
}

void RDMAServer::StartServer() {
	if (this->info_hints) {
		fi_freeinfo(this->info_hints);
	}
}

