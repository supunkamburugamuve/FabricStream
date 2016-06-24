#include <iostream>

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
/**
 * Initialize the server with options
 */
RDMAServer::RDMAServer(RDMAOptions *opts, struct fi_info *hints) {
	char *node, *service;
	uint64_t flags = 0;

	bool err;
    char *fi_str;
	this->options = opts;

	// allocate the hints
	this->info_hints = fi_allocinfo();
	if (!info_hints) {
		err = true;
	}

	// read the parameters from the options
	rdma_utils_read_addr_opts(&node, &service, this->info_hints, &flags, opts);

	// now lets retrieve the available network services
	// according to hints
	fi_getinfo(RDMA_FIVERSION, node, service, flags, info_hints, &this->info);
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

	// now lets incorporate the options

}

void RDMAServer::StartServer() {
	if (this->info_hints) {
		fi_freeinfo(this->info_hints);
	}
}
