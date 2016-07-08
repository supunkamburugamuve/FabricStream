#ifndef CONNECTION_H_
#define CONNECTION_H_

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
    int ExchangeKeys(struct fi_rma_iov *peer_iov);
    int sync();
    /**
     * Post a message
     */
    ssize_t PostRMA(enum rdma_rma_opcodes op, size_t size,
    		struct fi_rma_iov *remote);
    ssize_t RMA(enum rdma_rma_opcodes op, size_t size,
			struct fi_rma_iov *remote);
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


	struct fi_cq_attr cq_attr;
	struct fi_cntr_attr cntr_attr;
	struct fi_av_attr av_attr;

	struct fid_cq *txcq, *rxcq;
	struct fid_cntr *txcntr, *rxcntr;

	struct fid_wait *waitset;

	int rx_fd = -1, tx_fd = -1;

	struct fi_context tx_ctx, rx_ctx;

	// buffer used for communication
	void *buf, *tx_buf, *rx_buf;
	size_t buf_size, tx_size, rx_size;

	int ft_skip_mr = 0;

	uint64_t remote_cq_data;
	struct fid_mr *mr;
	struct fid_mr no_mr;

	// sequence numbers for messages posted and received
	uint64_t tx_seq, rx_seq, tx_cq_cntr, rx_cq_cntr;

	fi_addr_t remote_fi_addr;

	int timeout;

    ssize_t PostTX(struct fid_ep *ep, fi_addr_t fi_addr, size_t size, struct fi_context* ctx);
    ssize_t PostRX(struct fid_ep *ep, size_t size, struct fi_context* ctx);
    ssize_t TX(struct fid_ep *ep, fi_addr_t fi_addr, size_t size, struct fi_context *ctx);
    ssize_t RX(struct fid_ep *ep, size_t size);
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
};

#endif /* CONNECTION_H_ */
