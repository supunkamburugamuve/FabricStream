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
  int window_size;
  int transfer_size;
  char *src_port;
  char *dst_port;
  char *src_addr;
  char *dst_addr;
  char *av_name;
  int sizes_enabled;
  int options;
  enum rdma_comp_method comp_method;
  int machr;
  enum rdma_rma_opcodes rma_op;
  RDMAOptions();
};

#endif
