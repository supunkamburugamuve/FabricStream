#ifndef RDMA_SERVER_H_
#define RDMA_SERVER_H_

#include <list>
#include <map>
#include <utility>
#include <vector>

#include "utils.h"

class RDMAServer {
  public:
	RDMAServer(RDMAOptions *opts, struct fi_info *hints) ;
    int StartServer(void);
    // free all the resources
    void ShutDown();
  private:
    // options for initialization
    RDMAOptions *options;
    // fabric information obtained
    struct fi_info *info;
    // hints to be used to obtain fabric information
    struct fi_info *info_hints;
    // passive endpoint information
    // passive endpoint is used for connection management
    struct fi_info *pep_info;
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

    /**
     * Private methods
     */
    int AllocateReceive(struct fi_info *fi);
    int OpenFabric(void);
    int ServerConnect(void);
};

#endif
