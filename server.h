#ifndef RDMA_SERVER_H_
#define RDMA_SERVER_H_

#include <list>
#include <map>
#include <utility>
#include <vector>

#include "utils.h"



class RDMAServer {
  public:
    RDMAServer(RDMAOptions *opts);
    void StartServer();
    // free all the resources
    void ShutDown();
  private:
    // options for initialization
    RDMAOptions *options;
    // fabric information
    struct fi_info *info, *info_hints;
};

#endif
