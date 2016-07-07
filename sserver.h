#ifndef SSERVER_H_
#define SSERVER_H_

class SServer {
public:
	SServer(RDMAOptions *opts);
	void Free();
	virtual ~SServer();

	/**
	 * Start the server
	 */
	int Start(void);
	/**
	 * Accept new connections
	 */
	int Connect(void);
private:
	RDMAOptions *options;
	// hints to be used to obtain fabric information
	struct fi_info *info_hints;
	// hints to be used by passive endpoint
	struct fi_info *info_pep;
    // passive end-point for accepting connections
    struct fid_pep *pep;
    // the event queue to listen on for incoming connections
    struct fid_eq *eq;
    // event queue attribute
    struct fi_eq_attr eq_attr;
    // the fabric
    struct fid_fabric *fabric;
};


#endif /* SSERVER_H_ */
