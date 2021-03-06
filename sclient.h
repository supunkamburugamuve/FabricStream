#ifndef SCLIENT_H_
#define SCLIENT_H_

#include "connection.h"

class SClient {
public:
	SClient(RDMAOptions *opts, fi_info *hints);
	int Connect(void);
	/**
	 * Exchange keys with the peer
	 */
	int ExchangeKeys();
	/**
	 * Sync
	 */
	int sync();
	/**
	 * RMA
	 */
	ssize_t RMA(enum rdma_rma_opcodes op, size_t size);

	size_t Send(char *buf, size_t size);
	int Receive(char *buf, size_t *size);

	int Finalize(void);

	inline Connection *GetConnection() {
		return con;
	}

	virtual ~SClient();
private:
	// options for initialization
	RDMAOptions *options;
	// fabric information obtained
	struct fi_info *info;
	// hints to be used to obtain fabric information
	struct fi_info *info_hints;
	// the event queue to listen on for incoming connections
	struct fid_eq *eq;
	// event queue attribute
	struct fi_eq_attr eq_attr;
	// the fabric
	struct fid_fabric *fabric;
	// the connection
	Connection *con;
};

#endif /* SCLIENT_H_ */
