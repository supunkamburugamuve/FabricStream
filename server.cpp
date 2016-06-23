#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "server.h"

/**
 * Initialize the server with options
 */
RDMAServer::RDMAServer(RDMAOptions *opts) {
	bool err;
        char *fi_str;
	this->options = opts;
	this->hints = fi_allocinfo();
	if (!hints) {
		err = true;
	}
	// now lets retrieve the available network services
	fi_getinfo(RDMA_FIVERSION, NULL, NULL, FI_PROV_ATTR_ONLY, hints, &this->fi);
	if (this->fi) {
		fi_info *next = this->fi;
		while (next) {
			fi_str = fi_tostr(next, FI_TYPE_INFO);
                        printf("FI %s\n", fi_str);
                        next = next->next;
		}
	}
}

void RDMAServer::StartServer() {

}
