#include <list>
#include <map>
#include <utility>
#include <vector>

#include "utils.h"

#ifndef RDMA_FIVERSION
#define RDMA_FIVERSION FI_VERSION(1,3)
#endif

class RDMAServer {
  public:
    RDMAServer(RDMAOptions *opts);
    void StartServer();
  private:
    // options for initialization
    RDMAOptions *options;
    // fabric information
    struct fi_info *fi, *hints;
};

