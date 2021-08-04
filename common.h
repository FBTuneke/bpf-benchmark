#include "../linux/usr/include/linux/bpf.h"
#include "../linux/usr/include/linux/io_uring.h"
#include <stdbool.h>

#define DEFAULT_CQ_IDX 0
#define SINK_CQ_IDX 1

#define PROG_OFFSET 0
#define TEST_PROG_OFFSET 1

#define MAX_LOOP 100000

typedef struct _context
{
      int fd;
      char *char_to_send_userspace_ptr;
      char with_link;
      unsigned int count;
      unsigned int batch_size;
      unsigned int program_end;
} context_t;