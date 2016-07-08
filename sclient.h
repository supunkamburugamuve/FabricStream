/*
 * sclient.h
 *
 *  Created on: Jul 7, 2016
 *      Author: supun
 */

#ifndef SCLIENT_H_
#define SCLIENT_H_

class SClient {
public:
	SClient(RDMAOptions *opts);
	int Connect(void);
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
};

#endif /* SCLIENT_H_ */
