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
    void StartServer();
    // free all the resources
    void ShutDown();
  private:

    // options for initialization
    RDMAOptions *options;
    // fabric information
    struct fi_info *info, *info_hints;
    // the fabric
    struct fid_fabric *fabric;
    struct fi_eq_attr eq_attr;
    struct fid_eq *eq;
    struct fid_domain *domain;

    int OpenFabric(void);
};

#endif
