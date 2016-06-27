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
    size_t buf_size, tx_size, rx_size;

    /**
     * Private methods
     */
    int AllocateReceive(struct fi_info *fi);
    int OpenFabric(void);
    int ServerConnect(void);
    int AllocateActiveRes(struct fi_info *hints, struct fi_info *fi);
    int InitEp(struct fi_info *fi, struct fi_info *hints);
};

#endif
