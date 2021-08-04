// #include <cassert>
// #include <thread>
// #include <atomic>
// #include <iostream>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/resource.h>

#include "common.h"
#include "../linux/tools/lib/bpf/libbpf.h"
#include "../linux/tools/lib/bpf/bpf.h"
#include "liburing.h"
#include <sys/mman.h>
#include <stdlib.h>

#define QUEUE_DEPTH 1024

context_t *context_ptr;

#define NR_OF_BPF_PROGS 1

// using namespace std;

static void sig_handler(const int sig) 
{
      printf("Signal handled: %i.\n", sig);

      //BPF-Programm sagen es soll anhalten.
      __sync_fetch_and_add(&context_ptr->program_end, 1);

      exit(1);
      return;
}

static int libbpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static size_t roundup_page(size_t sz)
{
      long page_size = sysconf(_SC_PAGE_SIZE);
      return (sz + page_size - 1) / page_size * page_size;
}

#ifndef __NR_io_uring_register
      #define __NR_io_uring_register 427
#endif

int __sys_io_uring_register(int fd, unsigned opcode, const void *arg, unsigned nr_args)
{
	return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

      //Noetig, damit Speicher für bpf-Programm + Maps allokiert werden kann. Stand zumindest in einigen "Tutorials"
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

#define ARRAY_SIZE(x) ((unsigned)(sizeof(x) / sizeof((x)[0])))

int main(void)
{
      // signal(SIGTERM, sig_handler);
      // signal(SIGINT, sig_handler);
      
      //atomic<uint64_t> count(0);

      int fd = open("/dev/null", O_WRONLY);
      // unsigned batch_size = atoi(getenv("BATCHSIZE") ?: "1");
      unsigned batch_size = MAX_LOOP;
      bool with_link = !!getenv("IO_LINK");

      printf("io_uring: BATCHSIZE: %d LINK: %d\n", batch_size, with_link);

      struct io_uring ring;
      struct io_uring_params params;
      uint32_t cq_sizes[2] = {4096, 4096};

      memset(&params, 0, sizeof(params));
      params.nr_cq = ARRAY_SIZE(cq_sizes); //Anzahl von zusätzlichen Completion Queues???
	params.cq_sizes = (__u64)(unsigned long)cq_sizes; //will hier wohl einen Pointer?! 
      printf("Anzahl an CQs: %i\n", params.nr_cq);
      if (io_uring_queue_init_params(4096, &ring, &params) < 0){
            perror("io_uring_init_failed...\n");
            exit(1);
      }

      struct io_uring_cqe ** cqes = (struct io_uring_cqe **) malloc(QUEUE_DEPTH * sizeof(struct _io_uring_cqe *));

      libbpf_set_print(libbpf_print); //setze libbpf error und debug callback
      bump_memlock_rlimit(); //Fuer bpf, damit genug Speicher für BPF-Programm/Maps/etc. allokiert werden kann, ist aber glaube ich nicht mehr noetig. (https://nakryiko.com/posts/libbpf-bootstrap/)

      printf("-----------Opening BPF-Program\n");
      struct bpf_object *bpf_obj = bpf_object__open("ebpf.o");
      printf("-----------Done opening BPF-Program\n");
      
      printf("-----------Loading BPF-Program\n");
      int rc = bpf_object__load(bpf_obj);           
      printf("-----------Done Loading BPF-Program\n");
      if(rc < 0){
            printf("Error bpf_object__load, ret: %i\n", rc);
            return -1;
      }

      struct bpf_program *bpf_prog;
      int prog_fds[NR_OF_BPF_PROGS];

      for(int i = 0; i < NR_OF_BPF_PROGS; i++)
      {
            if(i == 0) bpf_prog = bpf_program__next(NULL, bpf_obj);
            else bpf_prog = bpf_program__next(bpf_prog, bpf_obj);

            const char *name = bpf_program__name(bpf_prog);
            printf("program %i name: %s\n", i, name);
            name = bpf_program__section_name(bpf_prog);
            printf("program %i section name: %s\n", i, name);          
            // int_temp = bpf_program__size(bpf_prog);
            // printf("program size: %i\n", int_temp);

            prog_fds[i] = bpf_program__fd(bpf_prog);
            printf("bpf-program %i fd: %i\n", i, prog_fds[i]);
      } 

      int context_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "context_map");
      printf("context_map_fd: %i\n", context_map_fd);

      size_t map_sz = roundup_page(1 * sizeof(context_t));
      void *mmapped_context_map_ptr = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, context_map_fd, 0);
      if (mmapped_context_map_ptr == MAP_FAILED || !mmapped_context_map_ptr){
            printf("mmap context map error \n");
            return -1;
      }

      char to_send = 'a';

      context_ptr = (context_t*) mmapped_context_map_ptr;
      context_ptr->fd = fd;
      context_ptr->char_to_send_userspace_ptr = &to_send;
      context_ptr->count = 0;
      context_ptr->with_link = (char)with_link;
      context_ptr->batch_size = batch_size;
      context_ptr->program_end = 0;

      rc = __sys_io_uring_register(ring.ring_fd, IORING_REGISTER_BPF, prog_fds, NR_OF_BPF_PROGS);
      if(rc < 0){
            printf("Error __sys_io_uring_register, ret: %i\n", rc);
            return -1;
      }

      struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
      if (!sqe){
            printf("get sqe #1 failed\n");
            return -1;
      }
      io_uring_prep_nop(sqe);
	sqe->off = PROG_OFFSET;
	sqe->opcode = IORING_OP_BPF;
      sqe->flags = 0;
      sqe->cq_idx = SINK_CQ_IDX;

      printf("Vor First Submit aus Userspace\n");

      rc = io_uring_submit(&ring);
      if (rc <= 0) {
            printf("sqe submit failed: %i\n", rc);
            return -1;
      }

      printf("Nach First Submit in Userspace\n");

      struct io_uring_cqe *cqe;

      // rc = io_uring_wait_cqe(&ring, &cqe);
      // io_uring_cqe_seen(&ring, cqe);

        
      // printf("\ncqe->user_data: %llu\n", cqe->user_data);
      // printf("cqe->res: %i\n", cqe->res);

      // thread t([&]() {
	    
      //       int cqe_count = io_uring_wait_cqe_nr(&ring, cqes, batch_size);
      //       count += cqe_count;
      //       printf("recv %d\n", cqe_count);
      //       // assert(cqe_count > 0);
      //       io_uring_cq_advance(&ring, cqe_count);

      // });

      while(1){
            // sleep(1);

            // int cqe_count = io_uring_wait_cqe_nr(&ring, cqes, 10);
            // int cqe_count = io_uring_wait_cqes(&ring, cqes, 10, NULL, NULL);
            
            //--
            // int sqe_count = io_uring_submit_and_wait(&ring, 1);

            // int cqe_count = io_uring_peek_batch_cqe(&ring, cqes, 1);
            // count += cqe_count;
            // printf("recv %d\n", cqe_count);
            // io_uring_cq_advance(&ring, cqe_count);
            //--

            // io_uring_submit(&ring);
            // printf("New Submit\n");

            int ret = io_uring_wait_cqe(&ring, &cqe);
            io_uring_cqe_seen(&ring, cqe);
            
            printf("cqe->user_data: %llu\n", cqe->user_data);
            printf("cqe->res: %i\n", cqe->res);

            // auto c = __sync_fetch_and_and(&context_ptr->count, zero)/1e6;
            // auto c = count.exchange(0)/1e6;

            // cout << c << endl;
      }

      return 0;
}     

