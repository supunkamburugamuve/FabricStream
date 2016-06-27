#ifndef RDMA_CLIENT_H_
#define RDMA_CLIENT_H_

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "utils.h"

class RDMACLient {
public:
  RDMACLient(RDMAOptions *opts, struct fi_info *hints);
  int StartClient(void);
  // free all the resources
  void ShutDown();
private:
  // options for initialization
  RDMAOptions *options;
  // fabric information obtained
  struct fi_info *info;
  // hints to be used to obtain fabric information
  struct fi_info *info_hints;
  // the fabric
  struct fid_fabric *fabric;
  struct fi_eq_attr eq_attr;
  // the event queue to listen on
  struct fid_eq *eq;
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
  size_t buf_size, tx_size, rx_size;
  /**
   * Private methods
   */
  int AllocateReceive(struct fi_info *fi);
  int OpenFabric(void);
  int ClientConnect(void);
  int InitEp(struct fi_info *hints, struct fi_info *fi);
  int AllocateActiveRes(struct fi_info *hints, struct fi_info *fi);
};

#endif
