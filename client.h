#ifndef RDMA_CLIENT_H_
#define RDMA_CLIENT_H_

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

  /**
   * Private methods
   */
  int AllocateReceive(struct fi_info *fi);
  int OpenFabric(void);
  int ClientConnect(void);
};

#endif
