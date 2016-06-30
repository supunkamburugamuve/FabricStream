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

#define ADDR_OPTS "b:p:s:a:r:"
#define INFO_OPTS "n:f:e:"

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

enum {
	FT_OPT_ACTIVE		= 1 << 0,
	FT_OPT_ITER		= 1 << 1,
	FT_OPT_SIZE		= 1 << 2,
	FT_OPT_RX_CQ		= 1 << 3,
	FT_OPT_TX_CQ		= 1 << 4,
	FT_OPT_RX_CNTR		= 1 << 5,
	FT_OPT_TX_CNTR		= 1 << 6,
	FT_OPT_VERIFY_DATA	= 1 << 7,
	FT_OPT_ALIGN		= 1 << 8,
	FT_OPT_BW		= 1 << 9,
};


class RDMAOptions {
public:
  char *src_port;
  char *dst_port;
  char *src_addr;
  char *dst_addr;
  char *fname;
  int options;
  char *av_name;
  /**
   * Computation method, spin, wait or wait-set
   */
  enum rdma_comp_method comp_method;

  RDMAOptions();
};

#define FT_EP_BIND(ep, fd, flags)					\
	do {								\
		int ret;						\
		if ((fd)) {						\
			ret = fi_ep_bind((ep), &(fd)->fid, (flags));	\
			if (ret) {					\
				printf("fi_ep_bind %d\n", ret);		\
				return ret;				\
			}						\
		}							\
	} while (0)

#define MAX(a,b) (((a)>(b))?(a):(b))

#define FT_MAX_CTRL_MSG 64
#define FT_STR_LEN 32
#define FT_MR_KEY 0xC0DE
#define FT_MSG_MR_ACCESS (FI_SEND | FI_RECV)
#define FT_RMA_MR_ACCESS (FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE)

/**
 * Given the options, create node, service, hints and flags
 */
int rdma_utils_read_addr_opts(char **node, char **service, struct fi_info *hints,
		uint64_t *flags, RDMAOptions *opts);
int rdma_utils_set_rma_caps(struct fi_info *fi);
int ft_get_cq_fd(RDMAOptions *opts, struct fid_cq *cq, int *fd);
int rdma_utils_get_info(RDMAOptions *options, struct fi_info *hints, struct fi_info **info);
void rdma_utils_cq_set_wait_attr(RDMAOptions *opts, struct fid_wait *waitset, struct fi_cq_attr *cq_attr);
void rdma_utils_cntr_set_wait_attr(RDMAOptions *opts, struct fid_wait *waitset, struct fi_cntr_attr *cntr_attr);

size_t rdma_utils_rx_prefix_size(struct fi_info *fi);
size_t rdma_utils_tx_prefix_size(struct fi_info *fi);
uint64_t rdma_utils_init_cq_data(struct fi_info *info);
static uint64_t rdma_utils_caps_to_mr_access(uint64_t caps);

#endif
