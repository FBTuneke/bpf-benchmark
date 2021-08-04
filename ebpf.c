#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "../linux/tools/lib/bpf/bpf_helpers.h"

struct bpf_map_def SEC("maps") context_map =
{
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(unsigned int),
        .value_size = sizeof(context_t),
        .max_entries = 1,
        .map_flags = BPF_F_MMAPABLE,
};

static long (*iouring_queue_sqe)(void *bpf_ctx, struct io_uring_sqe *sqe, unsigned int sqe_len) = (void *) 164;
static long (*iouring_emit_cqe)(void *bpf_ctx, unsigned int cq_idx, __u64 user_data, int res, unsigned int flags) = (void *) 165;
static long (*iouring_reap_cqe)(void *bpf_ctx, unsigned int cq_idx, struct io_uring_cqe *cqe_out, unsigned int cqe_len) = (void *) 166;

static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,const void *addr, unsigned len, __u64 offset)
{
	sqe->opcode = op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->rw_flags = 0;
	sqe->user_data = 0;
	sqe->__pad2[0] = sqe->__pad2[1] = sqe->__pad2[2] = 0;
}

static inline void io_uring_prep_bpf(struct io_uring_sqe *sqe, __u64 off,  __u64 user_data)
{
	io_uring_prep_rw(IORING_OP_BPF, sqe, 0, NULL, 0, off);   
	sqe->user_data = user_data;
}

SEC("iouring.s/prog") //.s = .is_sleepable = true
int prog(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
      unsigned int key = 0;
      context_t *context_ptr;
      
      context_ptr = (context_t *) bpf_map_lookup_elem(&context_map, &key); 
      if(!context_ptr)
      {
            // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, 27, 277, 0); //Aus Kernelmodus zurückkehren
            return 0;  
      } 

      // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, context_ptr->batch_size, 8888, 0);

      // return 0;

      if(context_ptr->batch_size > MAX_LOOP) return 0; //Für Verifier

      for(int i = 0; i < context_ptr->batch_size; i++)
      {
            io_uring_prep_rw(IORING_OP_WRITE, &sqe, context_ptr->fd, context_ptr->char_to_send_userspace_ptr, 1, 0);
            sqe.cq_idx = DEFAULT_CQ_IDX;
            if(context_ptr->with_link) sqe.flags = IOSQE_IO_HARDLINK;                 
            sqe.user_data = 1014;
            iouring_queue_sqe(ctx, &sqe, sizeof(sqe));   
      }

      if(context_ptr->end == 0){
            //Wieder selbst aufrufen
            io_uring_prep_bpf(&sqe, PROG_OFFSET, 0);  
            sqe.cq_idx = SINK_CQ_IDX;
            sqe.user_data = 9004;
            iouring_queue_sqe(ctx, &sqe, sizeof(sqe));
      }
    
      return 0;
}