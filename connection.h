#ifndef CONNECTION_H_
#define CONNECTION_H_

#include "buffer.h"

class Connection {
public:
	Connection(RDMAOptions *opts, struct fi_info *info_hints,
			struct fi_info *info, struct fid_fabric *fabric,
			struct fid_domain *domain, struct fid_eq *eq);
	/**
	 * Allocate the resources for this connection
	 */
	int AllocateActiveResources();
	/**
	 * Set and initialize the end point
	 */
	int InitEp(struct fid_ep *ep, struct fid_eq *eq);
	virtual ~Connection();

	/**
	 * Exchange keys with the peer
	 */
    int ExchangeKeysServer();
    int ExchangeKeysClient();
    int sync();
    /**
     * Post a message
     */
    ssize_t PostRMA(enum rdma_rma_opcodes op, size_t size,
    		struct fi_rma_iov *remote);
    ssize_t PostRMA(enum rdma_rma_opcodes op, size_t size, void *buf);
    ssize_t RMA(enum rdma_rma_opcodes op, size_t size,
			struct fi_rma_iov *remote);

    ssize_t TX(size_t size);
    ssize_t RX(size_t size);
    /**
     * Send the content in the buffer. Use multiple buffers if needed to send
     */
    int send(uint8_t *buf, size_t size);
    /**
     * Receive content in to the buffer.
     */
    int receive(uint8_t *buf, size_t buf_size, size_t *read);
    int Finalize(void);
private:
	// options for initialization
	RDMAOptions *options;
	// fabric information obtained
	struct fi_info *info;
	// hints to be used to obtain fabric information
	struct fi_info *info_hints;
	// the fabric
	struct fid_fabric *fabric;
	// fabric domain we are working with
	struct fid_domain *domain;
	// end point
	struct fid_ep *ep, *alias_ep;
	// address vector
	struct fid_av *av;

	// cq attribute for getting completion notifications
	struct fi_cq_attr cq_attr;
	// cntr attribute for getting counter notifications
	struct fi_cntr_attr cntr_attr;
	// vector attribute for getting completion notifications
	struct fi_av_attr av_attr;

	struct fid_cq *txcq, *rxcq;
	struct fid_cntr *txcntr, *rxcntr;

	struct fid_wait *waitset;

	int rx_fd = -1, tx_fd = -1;

	struct fi_context tx_ctx, rx_ctx;

	// buffer used for communication
	void *buf, *tx_buf, *rx_buf;
	size_t buf_size, tx_size, rx_size;
	Buffer *recv_buf;
	Buffer *send_buf;

	int ft_skip_mr = 0;

	uint64_t remote_cq_data;
	struct fid_mr *mr;
	struct fid_mr no_mr;

	// sequence numbers for messages posted and received
	uint64_t tx_seq, rx_seq, tx_cq_cntr, rx_cq_cntr;

	fi_addr_t remote_fi_addr;

	// remote address
	struct fi_rma_iov remote;

	int timeout;

    ssize_t PostTX(size_t size, struct fi_context* ctx);
    ssize_t PostRX(size_t size, struct fi_context* ctx);
    int GetTXComp(uint64_t total);
    int GetRXComp(uint64_t total);
    int GetCQComp(struct fid_cq *cq, uint64_t *cur,
    			  uint64_t total, int timeout);
    int FDWaitForComp(struct fid_cq *cq, uint64_t *cur,
    			    uint64_t total, int timeout);
    int WaitForCompletion(struct fid_cq *cq, uint64_t *cur,
    			    uint64_t total, int timeout);
    int SpinForCompletion(struct fid_cq *cq, uint64_t *cur,
    			    uint64_t total, int timeout);
    int AllocMsgs(void);
    int AllocateBuffers(void);
};

#endif /* CONNECTION_H_ */
