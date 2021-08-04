#include "../linux/usr/include/linux/bpf.h"
#include "../linux/usr/include/linux/io_uring.h"

#define DEFAULT_CQ_IDX 0
#define SINK_CQ_IDX 1

#define PROG_OFFSET 0

#define MAX_LOOP 4096

typedef struct _context
{
      int fd;
      char char_to_send;
      char *char_to_send_userspace_ptr;
      char with_link;
      char end;
      unsigned int count;
      unsigned int batch_size;
} context_t;