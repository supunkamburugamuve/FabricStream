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
  int ClientConnect(void);
  int ExchangeKeys(struct fi_rma_iov *peer_iov);
  int Finalize(void);
  ssize_t PostRMA(enum rdma_rma_opcodes op, size_t size,
      		struct fi_rma_iov *remote);
      ssize_t RMA(enum rdma_rma_opcodes op, size_t size,
  			struct fi_rma_iov *remote);
  int sync();
  // free all the resources
  int ShutDown();
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
  struct fi_eq_attr eq_attr = {};
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

  struct fi_cq_attr cq_attr = {};
  struct fi_cntr_attr cntr_attr = {};
  struct fi_av_attr av_attr = {};

  struct fid_cq *txcq, *rxcq;
  struct fid_cntr *txcntr, *rxcntr;

  struct fid_wait *waitset;

  int rx_fd = -1, tx_fd = -1;

  struct fi_context tx_ctx, rx_ctx;

  void *buf, *tx_buf, *rx_buf;
  size_t buf_size, tx_size, rx_size;

  int ft_skip_mr = 0;

  uint64_t remote_cq_data;
  struct fid_mr *mr;
  struct fid_mr no_mr;

  uint64_t tx_seq, rx_seq, tx_cq_cntr, rx_cq_cntr;

  fi_addr_t remote_fi_addr;

  int timeout;
  /**
   * Private methods
   */
  int AllocateReceive(struct fi_info *fi);
  int OpenFabric(void);
  int OpenFabric2(void);

  int InitEp(struct fi_info *hints, struct fi_info *fi);
  int AllocateActiveRes(struct fi_info *hints, struct fi_info *fi);
  int AllocMsgs(void);

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
};

#endif
