#ifndef RDMA_UTILS_H_
#define RDMA_UTILS_H_

#include <string>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#define ADDR_OPTS "b:p:s:a:"
#define INFO_OPTS "n:f:e:r:"

enum rdma_comp_method {
	FT_COMP_SPIN = 0,
	FT_COMP_SREAD,
	FT_COMP_WAITSET,
	FT_COMP_WAIT_FD
};

enum rdma_rma_opcodes {
	FT_RMA_READ = 1,
	FT_RMA_WRITE,
	FT_RMA_WRITEDATA,
};


class RDMAOptions {
public:
  char *src_port;
  char *dst_port;
  char *src_addr;
  char *dst_addr;

  RDMAOptions();
};

/**
 * Given the options, create node, service, hints and flags
 */
int rdma_utils_read_addr_opts(char **node, char **service, struct fi_info *hints,
		uint64_t *flags, RDMAOptions *opts);

#endif
