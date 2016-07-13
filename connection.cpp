#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstdlib>
#include <cstring>

#include <algorithm>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "utils.h"
#include "connection.h"

Connection::Connection(RDMAOptions *opts, struct fi_info *info_hints,
		struct fi_info *info, struct fid_fabric *fabric, struct fid_domain *domain, struct fid_eq *eq) {
	this->options = opts;
	this->info = info;
	this->info_hints = info_hints;
	this->fabric = fabric;
	this->domain = domain;

	this->txcq = NULL;
	this->rxcq = NULL;
	this->txcntr = NULL;
	this->rxcntr = NULL;

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
	this->recv_buf = NULL;
	this->send_buf = NULL;

	this->remote_cq_data = 0;
	this->waitset = NULL;


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

	this->cq_attr.wait_obj = FI_WAIT_NONE;
	this->cntr_attr.events = FI_CNTR_EVENTS_COMP;
	this->cntr_attr.wait_obj = FI_WAIT_NONE;

	this->av_attr.type = FI_AV_MAP;
	this->av_attr.count = 1;

	this->remote_fi_addr = FI_ADDR_UNSPEC;
	this->remote = {};

	this->timeout = -1;
}

int Connection::AllocateActiveResources() {
	int ret;
	printf("Allocate recv\n");
	if (info_hints->caps & FI_RMA) {
		ret = rdma_utils_set_rma_caps(info);
		if (ret)
			return ret;
	}

	ret = AllocMsgs();
	if (ret) {
		return ret;
	}

	if (cq_attr.format == FI_CQ_FORMAT_UNSPEC) {
		if (info->caps & FI_TAGGED) {
			cq_attr.format = FI_CQ_FORMAT_TAGGED;
		} else {
			cq_attr.format = FI_CQ_FORMAT_CONTEXT;
		}
	}

	if (this->options->options & FT_OPT_TX_CQ) {
		rdma_utils_cq_set_wait_attr(this->options, this->waitset, &this->cq_attr);
		cq_attr.size = info->tx_attr->size;
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
		cq_attr.size = info->rx_attr->size;
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

	if (this->info->ep_attr->type == FI_EP_RDM || this->info->ep_attr->type == FI_EP_DGRAM) {
		if (this->info->domain_attr->av_type != FI_AV_UNSPEC) {
			av_attr.type = info->domain_attr->av_type;
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

	return 0;
}

int Connection::AllocateBuffers(void) {
	int ret;
	RDMAOptions *opts = this->options;
	bool align = false;

	size_t buffer_size = opts->buf_size;
	if (buffer_size > info->ep_attr->max_msg_size) {
		buffer_size = info->ep_attr->max_msg_size;
	}
	buffer_size += rdma_utils_rx_prefix_size(this->info);
	buffer_size = MAX(buffer_size, FT_MAX_CTRL_MSG);

	recv_buf = new Buffer(NULL, buffer_size, opts->no_buffers);
	send_buf = new Buffer(NULL, buffer_size, opts->no_buffers);
	align = opts->options & FT_OPT_ALIGN ? true : false;
	recv_buf->Init(align);
	send_buf->Init(align);

	remote_cq_data = rdma_utils_init_cq_data(info);

	if (!ft_skip_mr && ((info->mode & FI_LOCAL_MR) ||
				(info->caps & (FI_RMA | FI_ATOMIC)))) {
		ret = fi_mr_reg(domain, buf, buf_size, rdma_utils_caps_to_mr_access(info->caps),
				0, FT_MR_KEY, 0, &mr, NULL);
		if (ret) {
			printf("fi_mr_reg %d\n", ret);
			return ret;
		}
	} else {
		mr = &no_mr;
	}
	return 0;
}

/*
 * Include FI_MSG_PREFIX space in the allocated buffer, and ensure that the
 * buffer is large enough for a control message used to exchange addressing
 * data.
 */
int Connection::AllocMsgs(void) {
	int ret;
	long alignment = 1;
	RDMAOptions *opts = this->options;

	tx_size = 10000;
	if (tx_size > info->ep_attr->max_msg_size) {
		tx_size = info->ep_attr->max_msg_size;
	}
	rx_size = tx_size + rdma_utils_rx_prefix_size(this->info);
	tx_size += rdma_utils_tx_prefix_size(this->info);
	buf_size = MAX(tx_size, FT_MAX_CTRL_MSG) + MAX(rx_size, FT_MAX_CTRL_MSG);

	if (opts->options & FT_OPT_ALIGN) {
		alignment = sysconf(_SC_PAGESIZE);
		if (alignment < 0)
			return -errno;
		buf_size += alignment;

		ret = posix_memalign(&buf, (size_t) alignment, buf_size);
		if (ret) {
			printf("posix_memalign %d\n", ret);
			return ret;
		}
	} else {
		buf = malloc(buf_size);
		if (!buf) {
			perror("malloc");
			return -FI_ENOMEM;
		}
	}
	memset(buf, 0, buf_size);
	rx_buf = buf;
	tx_buf = (char *) buf + MAX(rx_size, FT_MAX_CTRL_MSG);
	tx_buf = (void *) (((uintptr_t) tx_buf + alignment - 1) & ~(alignment - 1));
	remote_cq_data = rdma_utils_init_cq_data(info);

	if (!ft_skip_mr && ((info->mode & FI_LOCAL_MR) ||
				(info->caps & (FI_RMA | FI_ATOMIC)))) {
		ret = fi_mr_reg(domain, buf, buf_size, rdma_utils_caps_to_mr_access(info->caps),
				0, FT_MR_KEY, 0, &mr, NULL);
		if (ret) {
			printf("fi_mr_reg %d\n", ret);
			return ret;
		}
	} else {
		mr = &no_mr;
	}

	return 0;
}

int Connection::InitEp(struct fid_ep *ep, struct fid_eq *eq) {
	int flags, ret;
	printf("Init EP\n");

	this->ep = ep;
	if (this->info->ep_attr->type == FI_EP_MSG) {
		FT_EP_BIND(ep, eq, 0);
	}
	FT_EP_BIND(ep, av, 0);
	FT_EP_BIND(ep, txcq, FI_TRANSMIT);
	FT_EP_BIND(ep, rxcq, FI_RECV);

	ret = ft_get_cq_fd(this->options, txcq, &tx_fd);
	if (ret) {
		return ret;
	}

	ret = ft_get_cq_fd(this->options, rxcq, &rx_fd);
	if (ret) {
		return ret;
	}

	flags = !txcq ? FI_SEND : 0;
	if (this->info_hints->caps & (FI_WRITE | FI_READ)) {
		flags |= this->info_hints->caps & (FI_WRITE | FI_READ);
	} else if (this->info_hints->caps & FI_RMA) {
		flags |= FI_WRITE | FI_READ;
	}

	FT_EP_BIND(ep, txcntr, flags);
	flags = !rxcq ? FI_RECV : 0;
	if (this->info_hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ)) {
		flags |= this->info_hints->caps & (FI_REMOTE_WRITE | FI_REMOTE_READ);
	} else if (this->info_hints->caps & FI_RMA) {
		flags |= FI_REMOTE_WRITE | FI_REMOTE_READ;
	}
	FT_EP_BIND(ep, rxcntr, flags);
	ret = fi_enable(ep);
	if (ret) {
		printf("fi_enable %d\n", ret);
		return ret;
	}
	if (this->info->rx_attr->op_flags != FI_MULTI_RECV) {
		/* Initial receive will get remote address for unconnected EPs */
		ret = PostRX(MAX(rx_size, FT_MAX_CTRL_MSG), &rx_ctx);
		if (ret) {
			return ret;
		}
	}
	return 0;
}

#define FT_POST(post_fn, comp_fn, seq, op_str, ...)				\
	do {									\
		int timeout_save;						\
		int ret, rc;							\
										\
		while (1) {							\
			ret = post_fn(__VA_ARGS__);				\
			if (!ret)						\
				break;						\
										\
			if (ret != -FI_EAGAIN) {				\
				printf("%s %d\n", op_str, ret);			\
				return ret;					\
			}							\
										\
			timeout_save = timeout;					\
			timeout = 0;						\
			rc = comp_fn(seq);					\
			if (rc && rc != -FI_EAGAIN) {				\
				printf("Failed to get %s completion\n", op_str);	\
				return rc;					\
			}							\
			timeout = timeout_save;					\
		}								\
		seq++;								\
	} while (0)

/*
 * fi_cq_err_entry can be cast to any CQ entry format.
 */
int Connection::SpinForCompletion(struct fid_cq *cq, uint64_t *cur,
			    uint64_t total, int timeout) {
	struct fi_cq_err_entry comp;
	struct timespec a, b;
	int ret;

	if (timeout >= 0) {
		clock_gettime(CLOCK_MONOTONIC, &a);
	}

	while (total - *cur > 0) {
		ret = fi_cq_read(cq, &comp, 1);
		if (ret > 0) {
			if (timeout >= 0) {
				clock_gettime(CLOCK_MONOTONIC, &a);
			}

			(*cur)++;
		} else if (ret < 0 && ret != -FI_EAGAIN) {
			return ret;
		} else if (timeout >= 0) {
			clock_gettime(CLOCK_MONOTONIC, &b);
			if ((b.tv_sec - a.tv_sec) > timeout) {
				fprintf(stderr, "%ds timeout expired\n", timeout);
				return -FI_ENODATA;
			}
		}
	}

	return 0;
}

/*
 * fi_cq_err_entry can be cast to any CQ entry format.
 */
int Connection::WaitForCompletion(struct fid_cq *cq, uint64_t *cur,
			    uint64_t total, int timeout) {
	struct fi_cq_err_entry comp;
	int ret;

	while (total - *cur > 0) {
		ret = fi_cq_sread(cq, &comp, 1, NULL, timeout);
		if (ret > 0) {
			(*cur)++;
		}
		else if (ret < 0 && ret != -FI_EAGAIN) {
			return ret;
		}
	}

	return 0;
}

/*
 * fi_cq_err_entry can be cast to any CQ entry format.
 */
int Connection::FDWaitForComp(struct fid_cq *cq, uint64_t *cur,
			    uint64_t total, int timeout) {
	struct fi_cq_err_entry comp;
	struct fid *fids[1];
	int fd, ret;

	fd = cq == txcq ? tx_fd : rx_fd;
	fids[0] = &cq->fid;

	while (total - *cur > 0) {
		ret = fi_trywait(fabric, fids, 1);
		if (ret == FI_SUCCESS) {
			ret = rdma_utils_poll_fd(fd, timeout);
			if (ret && ret != -FI_EAGAIN) {
				return ret;
			}
		}

		ret = fi_cq_read(cq, &comp, 1);
		if (ret > 0) {
			(*cur)++;
		} else if (ret < 0 && ret != -FI_EAGAIN) {
			return ret;
		}
	}

	return 0;
}

int Connection::GetCQComp(struct fid_cq *cq, uint64_t *cur,
			  uint64_t total, int timeout) {
	int ret;

	switch (this->options->comp_method) {
	case FT_COMP_SREAD:
		ret = WaitForCompletion(cq, cur, total, timeout);
		break;
	case FT_COMP_WAIT_FD:
		ret = FDWaitForComp(cq, cur, total, timeout);
		break;
	default:
		ret = SpinForCompletion(cq, cur, total, timeout);
		break;
	}

	if (ret) {
		if (ret == -FI_EAVAIL) {
			ret = rdma_utils_cq_readerr(cq);
			(*cur)++;
		} else {
			printf("ft_get_cq_comp %d\n", ret);
		}
	}
	return ret;
}

int Connection::GetRXComp(uint64_t total) {
	int ret = FI_SUCCESS;

	if (rxcq) {
		ret = GetCQComp(rxcq, &rx_cq_cntr, total, timeout);
	} else if (rxcntr) {
		while (fi_cntr_read(rxcntr) < total) {
			ret = fi_cntr_wait(rxcntr, total, timeout);
			if (ret)
				printf("fi_cntr_wait %d\n", ret);
			else
				break;
		}
	} else {
		printf("Trying to get a RX completion when no RX CQ or counter were opened");
		ret = -FI_EOTHER;
	}
	return ret;
}

int Connection::GetTXComp(uint64_t total) {
	int ret;

	if (txcq) {
		ret = GetCQComp(txcq, &tx_cq_cntr, total, -1);
	} else if (txcntr) {
		ret = fi_cntr_wait(txcntr, total, -1);
		if (ret)
			printf("fi_cntr_wait %d\n", ret);
	} else {
		printf("Trying to get a TX completion when no TX CQ or counter were opened \n");
		ret = -FI_EOTHER;
	}
	return ret;
}

ssize_t Connection::PostTX(size_t size, struct fi_context* ctx) {
	if (info_hints->caps & FI_TAGGED) {
		FT_POST(fi_tsend, GetTXComp, tx_seq, "transmit", ep,
				tx_buf, size + rdma_utils_tx_prefix_size(info), fi_mr_desc(mr),
				this->remote_fi_addr, tx_seq, ctx);
	} else {
		FT_POST(fi_send, GetTXComp, tx_seq, "transmit", ep,
				tx_buf,	size + rdma_utils_tx_prefix_size(info), fi_mr_desc(mr),
				this->remote_fi_addr, ctx);
	}
	return 0;
}

ssize_t Connection::TX(size_t size) {
	ssize_t ret;

	if (rdma_utils_check_opts(options, FT_OPT_VERIFY_DATA | FT_OPT_ACTIVE))
		rdma_utils_fill_buf((char *) tx_buf + rdma_utils_tx_prefix_size(info), size);

	ret = PostTX(size, &this->tx_ctx);
	if (ret) {
		return ret;
	}

	ret = GetTXComp(tx_seq);
	return ret;
}

ssize_t Connection::PostRX(size_t size, struct fi_context* ctx) {
	if (info_hints->caps & FI_TAGGED) {
		FT_POST(fi_trecv, GetRXComp, rx_seq, "receive", this->ep, rx_buf,
				MAX(size, FT_MAX_CTRL_MSG) + rdma_utils_rx_prefix_size(info),
				fi_mr_desc(mr), 0, rx_seq, 0, ctx);
	} else {
		FT_POST(fi_recv, GetRXComp, rx_seq, "receive", this->ep, rx_buf,
				MAX(size, FT_MAX_CTRL_MSG) + rdma_utils_rx_prefix_size(info),
				fi_mr_desc(mr),	0, ctx);
	}
	return 0;
}

ssize_t Connection::RX(size_t size) {
	ssize_t ret;

	ret = GetRXComp(rx_seq);
	if (ret)
		return ret;

	if (rdma_utils_check_opts(options, FT_OPT_VERIFY_DATA | FT_OPT_ACTIVE)) {
		ret = rdma_utils_check_buf((char *) rx_buf + rdma_utils_rx_prefix_size(info), size);
		if (ret)
			return ret;
	}
	/* TODO: verify CQ data, if available */

	/* Ignore the size arg. Post a buffer large enough to handle all message
	 * sizes. ft_sync() makes use of ft_rx() and gets called in tests just before
	 * message size is updated. The recvs posted are always for the next incoming
	 * message */
	ret = PostRX(this->rx_size, &this->rx_ctx);
	return ret;
}

ssize_t Connection::PostRMA(enum rdma_rma_opcodes op, size_t size) {
	struct fi_rma_iov *remote = &this->remote;
	switch (op) {
	case FT_RMA_WRITE:
		FT_POST(fi_write, GetTXComp, tx_seq, "fi_write", ep, tx_buf,
				options->transfer_size, fi_mr_desc(mr), remote_fi_addr,
				remote->addr, remote->key, ep);
		break;
	case FT_RMA_WRITEDATA:
		FT_POST(fi_writedata, GetTXComp, tx_seq, "fi_writedata", ep,
				tx_buf, options->transfer_size, fi_mr_desc(mr),
				remote_cq_data,	remote_fi_addr,	remote->addr,
				remote->key, ep);
		break;
	case FT_RMA_READ:
		FT_POST(fi_read, GetTXComp, tx_seq, "fi_read", ep, rx_buf,
				options->transfer_size, fi_mr_desc(mr), remote_fi_addr,
				remote->addr, remote->key, ep);
		break;
	default:
		printf("Unknown RMA op type\n");
		return EXIT_FAILURE;
	}

	return 0;
}

ssize_t Connection::PostRMA(enum rdma_rma_opcodes op, size_t size, void *buf) {
	switch (op) {
	case FT_RMA_WRITE:
		FT_POST(fi_write, GetTXComp, tx_seq, "fi_write", ep, buf,
				size, fi_mr_desc(mr), remote_fi_addr,
				remote.addr, remote.key, ep);
		break;
	case FT_RMA_WRITEDATA:
		FT_POST(fi_writedata, GetTXComp, tx_seq, "fi_writedata", ep,
				buf, size, fi_mr_desc(mr),
				remote_cq_data,	remote_fi_addr,	remote.addr,
				remote.key, ep);
		break;
	case FT_RMA_READ:
		FT_POST(fi_read, GetTXComp, tx_seq, "fi_read", ep, buf,
				size, fi_mr_desc(mr), remote_fi_addr,
				remote.addr, remote.key, ep);
		break;
	default:
		printf("Unknown RMA op type\n");
		return EXIT_FAILURE;
	}

	return 0;
}

ssize_t Connection::RMA(enum rdma_rma_opcodes op, size_t size) {
	int ret;

	ret = PostRMA(op, size, &remote);
	if (ret)
		return ret;

	if (op == FT_RMA_WRITEDATA) {
		ret = RX(0);
		if (ret)
			return ret;
	}

	ret = GetTXComp(tx_seq);
	if (ret)
		return ret;

	return 0;
}



int Connection::ExchangeKeysServer() {
	struct fi_rma_iov *peer_iov = &this->remote;
	struct fi_rma_iov *rma_iov;
	int ret;

	ret = GetRXComp(rx_seq);
	if (ret) {
		printf("Failed to RX Completion\n");
		return ret;
	}

	rma_iov = (fi_rma_iov *)(static_cast<char *>(rx_buf) + rdma_utils_rx_prefix_size(info));
	*peer_iov = *rma_iov;
	ret = PostRX(rx_size, &rx_ctx);
	if (ret) {
		printf("Failed to post RX\n");
		return ret;
	}
	rma_iov = (fi_rma_iov *)(static_cast<char *>(tx_buf) + rdma_utils_tx_prefix_size(info));
	rma_iov->addr = info->domain_attr->mr_mode == FI_MR_SCALABLE ?
			0 : (uintptr_t) rx_buf + rdma_utils_rx_prefix_size(info);
	rma_iov->key = fi_mr_key(mr);
	ret = TX(sizeof *rma_iov);
	if (ret) {
		printf("Failed to TX\n");
		return ret;
	}
	return ret;
}

int Connection::ExchangeKeysClient() {
	struct fi_rma_iov *peer_iov = &this->remote;
	struct fi_rma_iov *rma_iov;
	int ret;

	rma_iov = (fi_rma_iov *)(static_cast<char *>(tx_buf) + rdma_utils_tx_prefix_size(info));
	rma_iov->addr = info->domain_attr->mr_mode == FI_MR_SCALABLE ?
			0 : (uintptr_t) rx_buf + rdma_utils_rx_prefix_size(info);
	rma_iov->key = fi_mr_key(mr);
	ret = TX(sizeof *rma_iov);
	if (ret) {
		printf("Failed to TX\n");
		return ret;
	}

	ret = GetRXComp(rx_seq);
	if (ret) {
		printf("Failed to get rx completion\n");
		return ret;
	}

	rma_iov = (fi_rma_iov *)(static_cast<char *>(rx_buf) + rdma_utils_rx_prefix_size(info));
	*peer_iov = *rma_iov;
	ret = PostRX(rx_size, &rx_ctx);
	if (ret) {
		printf("Failed to post RX\n");
		return ret;
	}
	return ret;
}

int Connection::sync() {
	int ret;
	ret = RX(1);
	if (ret) {
		return ret;
	}

	ret = TX(1);
	return ret;
}

int Connection::SendCompletions(uint64_t min, uint64_t max) {
	int ret;
	struct fi_cq_err_entry comp;
	struct timespec a, b;

	if (txcq) {
		if (timeout >= 0) {
			clock_gettime(CLOCK_MONOTONIC, &a);
		}

		while (tx_cq_cntr < max) {
			ret = fi_cq_read(txcq, &comp, 1);
			if (ret > 0) {
				if (timeout >= 0) {
					clock_gettime(CLOCK_MONOTONIC, &a);
				}
				tx_cq_cntr += ret;
				if (tx_cq_cntr >= max) {
					break;
				}
			} else if (ret < 0 && ret != -FI_EAGAIN) {
				return ret;
			} else if (min <= tx_cq_cntr && ret == -FI_EAGAIN) {
				// we have read enough to return
				break;
			} else if (timeout >= 0) {
				clock_gettime(CLOCK_MONOTONIC, &b);
				if ((b.tv_sec - a.tv_sec) > timeout) {
					fprintf(stderr, "%ds timeout expired\n", timeout);
					return -FI_ENODATA;
				}
			}
		}
	} else if (txcntr) {
		ret = fi_cntr_wait(txcntr, min, -1);
		if (ret) {
			printf("fi_cntr_wait %d\n", ret);
		}
	} else {
		printf("Trying to get a TX completion when no TX CQ or counter were opened \n");
		ret = -FI_EOTHER;
	}
	return ret;
}

/**
 * Receive completions at least 'total' completions and until rx_seq
 * completions
 */
int Connection::ReceiveCompletions(uint64_t min, uint64_t max) {
	int ret = FI_SUCCESS;
	struct fi_cq_err_entry comp;
	struct timespec a, b;
	uint64_t read;
	// in case we are using completion queue
	if (rxcq) {
		if (timeout >= 0) {
			clock_gettime(CLOCK_MONOTONIC, &a);
		}

		while (rx_cq_cntr < max	) {
			ret = fi_cq_read(rxcq, &comp, 1);
			if (ret > 0) {
				if (timeout >= 0) {
					clock_gettime(CLOCK_MONOTONIC, &a);
				}
				rx_cq_cntr += ret;
				// we've reached max
				if (rx_cq_cntr >= max) {
					break;
				}
			} else if (ret < 0 && ret != -FI_EAGAIN) {
				break;
			} else if (min <= rx_cq_cntr && ret == -FI_EAGAIN) {
				// we have read enough to return
				break;
			} else if (timeout >= 0) {
				clock_gettime(CLOCK_MONOTONIC, &b);
				if ((b.tv_sec - a.tv_sec) > timeout) {
					fprintf(stderr, "%ds timeout expired\n", timeout);
					ret = -FI_ENODATA;
					break;
				}
			}
		}

		if (ret) {
			if (ret == -FI_EAVAIL) {
				ret = rdma_utils_cq_readerr(rxcq);
				rx_cq_cntr++;
			} else {
				printf("ft_get_cq_comp %d\n", ret);
			}
		}
		return 0;
	} else if (rxcntr) { // we re using the counter
		while (1) {
			read = fi_cntr_read(rxcntr);
			if (read < min) {
				ret = fi_cntr_wait(rxcntr, min, timeout);
				rx_cq_cntr = read;
				if (ret) {
					printf("fi_cntr_wait %d\n", ret);
					break;
				} else {
					// we read up to min
					rx_cq_cntr = min;
				}
			} else {
				// we read something
				if (read > rx_cq_cntr) {
					rx_cq_cntr = read;
				} else {
					// nothing new is read, so break
					break;
				}
			}
		}
	} else {
		printf("Trying to get a RX completion when no RX CQ or counter were opened");
		ret = -FI_EOTHER;
	}
	return ret;
}

int Connection::receive() {
	int ret;
	Buffer *sbuf = this->recv_buf;
	uint32_t i = 0, data_head;
	uint32_t buffers = sbuf->NoOfBuffers();
    // now wait until a receive is completed
	ret = ReceiveCompletions(rx_cq_cntr + 1, rx_seq);
	// ok a receive is completed
	// mark the buffers with the data
	// now update the buffer according to the rx_cq_cntr and rx_cq
	data_head = rx_cq_cntr % buffers;
	sbuf->SetDataHead(data_head);
	return 0;
}

int Connection::WriteBuffers() {
	int ret = 0;
	uint64_t written_size = 0;
	uint32_t i = 0;
	uint32_t size = 0;

	Buffer *sbuf = this->send_buf;
	// now go through the buffers
	uint32_t head = sbuf->Head();
	uint32_t data_head = sbuf->DataHead();
	// send the content in the buffers
	for (i = head; i < data_head; i++) {
		void *buf = sbuf->GetBuffer(i);
		size = sbuf->ContentSize(i);
		ret = PostRMA(FT_RMA_WRITE, size, buf);
		if (ret) {
			return 1;
		}
		// now increment the buffer
		sbuf->IncrementHead();
	}
	return 0;
}

int Connection::WriteData(uint8_t *buf, size_t size) {
	int ret;
	// first lets get the available buffer
	Buffer *sbuf = this->send_buf;
	// now determine the buffer no to use
	uint64_t sent_size = 0;
	uint64_t current_size = 0;
	uint32_t head = 0;

	uint64_t buf_size = sbuf->BufferSize();
	// we need to send everything buy using the buffers available
	while (sent_size < size) {
		uint64_t free_space = sbuf->GetFreeSpace();
		// we have space in the buffers
		if (free_space > 0) {
			head = sbuf->Head();
			void *current_buf = sbuf->GetBuffer(head);
			// now lets copy from send buffer to current buffer chosen
			current_size = (size - sent_size) < buf_size ? size - sent_size : buf_size;
			memcpy(current_buf, buf + sent_size, current_size);
			// send the current buffer
			PostRMA(FT_RMA_WRITE, current_size, current_buf);
			// increment the head
			sbuf->IncrementHead();
		} else {
			// we should wait for at least one completion
			ret = SendCompletions(tx_cq_cntr + 1, tx_seq);
			if (ret) {
				printf("Failed to get tx completion %d\n", ret);
				return 1;
			}
			// now free the buffer
			sbuf->IncrementTail();
		}
	}
	return 0;
}


int Connection::Finalize(void) {
	struct iovec iov;
	int ret;
	struct fi_context ctx;
	void *desc = fi_mr_desc(mr);

	strcpy((char *)(static_cast<char *>(tx_buf) + rdma_utils_tx_prefix_size(info)), "fin");
	iov.iov_base = tx_buf;
	iov.iov_len = 4 + rdma_utils_tx_prefix_size(info);

	if (info_hints->caps & FI_TAGGED) {
		struct fi_msg_tagged tmsg;

		memset(&tmsg, 0, sizeof tmsg);
		tmsg.msg_iov = &iov;
		tmsg.desc = &desc;
		tmsg.iov_count = 1;
		tmsg.addr = remote_fi_addr;
		tmsg.tag = tx_seq;
		tmsg.ignore = 0;
		tmsg.context = &ctx;

		ret = fi_tsendmsg(ep, &tmsg, FI_INJECT | FI_TRANSMIT_COMPLETE);
	} else {
		struct fi_msg msg;

		memset(&msg, 0, sizeof msg);
		msg.msg_iov = &iov;
		msg.desc = &desc;
		msg.iov_count = 1;
		msg.addr = remote_fi_addr;
		msg.context = &ctx;

		ret = fi_sendmsg(ep, &msg, FI_INJECT | FI_TRANSMIT_COMPLETE);
	}
	if (ret) {
		printf("transmit %d\n", ret);
		return ret;
	}


	ret = GetTXComp(++tx_seq);
	if (ret)
		return ret;

	ret = GetRXComp(rx_seq);
	if (ret)
		return ret;

	return 0;
}


Connection::~Connection() {

}

