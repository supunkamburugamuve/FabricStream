#ifndef CONNECTION_H_
#define CONNECTION_H_

class Connection {
public:
	Connection();
	virtual ~Connection();
private:
	// options for initialization
	RDMAOptions *options;
	// fabric information obtained
	struct fi_info *info;
	// hints to be used to obtain fabric information
	struct fi_info *info_hints;
	// passive endpoint information
	// passive endpoint is used for connection management
	struct fi_info *info_pep;
	// the fabric
	struct fid_fabric *fabric;
	// event queue attribute
	struct fi_eq_attr eq_attr;
	// the event queue to listen on
	struct fid_eq *eq;
	// fabric domain we are working with
	struct fid_domain *domain;
	// passive end-point for accepting connections
	struct fid_pep *pep;
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
};

#endif /* CONNECTION_H_ */
