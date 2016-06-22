#include <cstdint>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "utils.h"

static int getaddr(char *node, char *service,
                   struct fi_info *hints, uint64_t flags) {
    int ret;
    struct fi_info *fi;

    if (!node && !service) {
        if (flags & FI_SOURCE) {
            hints->src_addr = NULL;
            hints->src_addrlen = 0;
        } else {
            hints->dest_addr = NULL;
            hints->dest_addrlen = 0;
        }
        return 0;
    }

    ret = fi_getinfo(FT_FIVERSION, node, service, flags, hints, &fi);
    if (ret) {
        FT_PRINTERR("fi_getinfo", ret);
        return ret;
    }
    hints->addr_format = fi->addr_format;

    if (flags & FI_SOURCE) {
        ret = dupaddr(&hints->src_addr, &hints->src_addrlen,
                      fi->src_addr, fi->src_addrlen);
    } else {
        ret = dupaddr(&hints->dest_addr, &hints->dest_addrlen,
                      fi->dest_addr, fi->dest_addrlen);
    }

    fi_freeinfo(fi);
    return ret;
}

int ft_getsrcaddr(char *node, char *service, struct fi_info *hints) {
    return getaddr(node, service, hints, FI_SOURCE);
}

int ft_read_addr_opts(char **node, char **service, struct fi_info *hints,
                      uint64_t *flags, struct ft_opts *opts)  {
    int ret;

    if (opts->dst_addr) {
        if (!opts->dst_port) {
            opts->dst_port = default_port;
        }

        ret = ft_getsrcaddr(opts->src_addr, opts->src_port, hints);
        if (ret)
            return ret;
        *node = opts->dst_addr;
        *service = opts->dst_port;
    } else {
        if (!opts->src_port)
            opts->src_port = default_port;

        *node = opts->src_addr;
        *service = opts->src_port;
        *flags = FI_SOURCE;
    }

    return 0;
}

int ft_getinfo(struct fi_info *hints, struct fi_info **info, struct ft_opts *opts) {
    char *node, *service;
    uint64_t flags = 0;
    int ret;

    ret = ft_read_addr_opts(&node, &service, hints, &flags, opts);
    if (ret)
        return ret;

    if (!hints->ep_attr->type)
        hints->ep_attr->type = FI_EP_RDM;

    ret = fi_getinfo(FT_FIVERSION, node, service, flags, hints, info);
    if (ret) {
        FT_PRINTERR("fi_getinfo", ret);
        return ret;
    }
    return 0;
}

int fs_init_fabric(void) {
    int ret;
    ret = ft_getinfo(hints, &fi);
    if (ret)
        return ret;

    ret = ft_open_fabric_res();
    if (ret)
        return ret;

    if (hints->caps & FI_RMA) {
        ret = ft_set_rma_caps(fi, opts.rma_op);
        if (ret)
            return ret;
    }

    ret = ft_alloc_active_res(fi);
    if (ret)
        return ret;

    ret = ft_init_ep();
    if (ret)
        return ret;

    ret = ft_init_av();
    if (ret)
        return ret;

    return 0;
}



