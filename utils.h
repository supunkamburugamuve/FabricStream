#include <string>

char default_port[8] = "9228";

struct fs_opts {
  int iterations;
  int warmup_iterations;
  int transfer_size;
  int window_size;
  char *src_port;
  char *dst_port;
  char *src_addr;
  char *dst_addr;
  char *av_name;
  int sizes_enabled;
  int options;
  enum ft_comp_method comp_method;
  int machr;
  enum ft_rma_opcodes rma_op;
  int argc;
  char **argv;
};

void utils_parse_info(int op, char *optarg, struct fi_info *hints);