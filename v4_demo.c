#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include <scsi/sg.h>
#include <linux/bsg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <byteswap.h>

#define printf_log(__fmt, ...)					\
	do {							\
		fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);	\
		fprintf(stderr, __fmt, ##__VA_ARGS__);		\
	} while(0)

struct capacity16 {
	union {
		uint8_t value;
		struct {
			uint8_t prot_en : 1;
			uint8_t p_type  : 3;
		};
	} prot_info;
	uint32_t lb_len;
	uint32_t lba_min;
	uint64_t lba_max;
};

void dump_capacity16(struct capacity16 *cap)
{
	printf_log("lb_len = %lu\nlba_min = %lu\nlba_max = %lu\n"
		   "prot_en = %lu\np_type = %lu\n",
		   cap->lb_len, cap->lba_min, cap->lba_max,
		   cap->prot_info.prot_en, cap->prot_info.p_type);
}

int v4_read_capacity16(int fd, struct capacity16 *cap)
{
	uint8_t cdb[16] = { };
	uint8_t data[32] = { };
	cdb[0] = 0x9e;
	cdb[1] = 0x10;
	*((uint32_t*) &cdb[10]) = bswap_32(sizeof(data));

	struct sg_io_v4 hdr = {
		.guard			= 'Q',
		.request_len		= sizeof(cdb),
		.request		= (uintptr_t) cdb,
		.din_xfer_len		= sizeof(data),
		.din_xferp		= (uintptr_t) data,
	};

	if (ioctl(fd, SG_IO, &hdr) < 0) {
		perror("ioctl");
		return -1;
	}

	cap->lba_max = bswap_64(*((uint64_t*) &data[0]));
	cap->lb_len  = bswap_32(*((uint32_t*) &data[8]));
	cap->prot_info.p_type  = data[12] & (uint8_t) 0b00001110;
	cap->prot_info.prot_en = data[12] & (uint8_t) 1;
	cap->lba_min = (data[14] & 0b00111111) << 8 + data[15];

	return 0;
}

static inline void
v4_init_cdb_read16(uint8_t *cdb, uint64_t lba, uint32_t tr_len)
{
	memset(cdb, 0, 16);
	cdb[0] = 0x88;
	cdb[1] = (uint8_t) 0b01100000;
	*((uint64_t*) &cdb[2])  = bswap_64(lba);
	*((uint32_t*) &cdb[10]) = bswap_32(tr_len);
}

static inline void
v4_init_hdr_read16(struct sg_io_v4 *hdr, uint8_t *cdb,
		   uint64_t lba, uint32_t tr_len,
		   uint8_t *buf, uint32_t buf_len)
{
	v4_init_cdb_read16(cdb, lba, tr_len);
	memset(hdr, 0, sizeof(*hdr));
	hdr->guard		= 'Q';
	hdr->request_len	= 16;
	hdr->request		= (uintptr_t) cdb;
	hdr->din_xfer_len	= buf_len;
	hdr->din_xferp		= (uintptr_t) buf;
}

static inline int rand_ranged(int min, int max)
{
	return rand() % (max - min) + min;
}

int fd_enable_async_rt(int fd, int rt_sig)
{
	int flags = fcntl(fd, F_GETFL, NULL);
	if (flags == -1)
		goto handle_err0;

	if (fcntl(fd, F_SETFL, flags | O_ASYNC) < 0)
		goto handle_err0;

	if (fcntl(fd, F_SETSIG, rt_sig) < 0)
		goto handle_err1;

	return 0;

handle_err1:
	fcntl(fd, F_SETFL, flags);
handle_err0:
	perror("fcntl");
	return -1;
}

struct async_info {
	int 		 	 sg_fd;
	volatile sig_atomic_t	 status;
	struct capacity16	*cap;
	struct sg_io_v4 	*ctl;
} g_async_info;

void async_handler(int sig)
{
	int 			 sg_fd	 = g_async_info.sg_fd;
	struct capacity16	*cap	 = g_async_info.cap;
	struct sg_io_v4		*ctl	 = g_async_info.ctl;
	struct sg_io_v4		*req_arr = (void*) ctl->dout_xferp;

	/* Receive some requests */
	int ret = ioctl(sg_fd, SG_IORECEIVE, ctl);
	if (ret < 0 || (errno = ctl->spare_out)) {
		perror("ioctl");
		goto handle_err;
	}

	/* Reinitialize some request array entries */
	int n_received = ctl->din_resid;

	for (int i = 0; i < n_received; i++) {
		int n = req_arr[i].usr_ptr; /* Identify received request */
		printf_log("RECEIVED: req[%d]\n", n);

		v4_init_hdr_read16(req_arr + i, (void*) req_arr[i].request,
			rand_ranged(cap->lba_min, cap->lba_max),
			1, (void*) req_arr[i].din_xferp, cap->lb_len);

		req_arr[i].usr_ptr = i;
	}

	/* Submit new read16 requests */
	ctl->request_len   = n_received * 16;
	ctl->dout_xfer_len = n_received * sizeof(struct sg_io_v4);

	ret = ioctl(sg_fd, SG_IOSUBMIT, ctl);
	if (ret < 0 || (errno = ctl->spare_out)) {
		perror("ioctl");
		goto handle_err;
	}

	return;

	sigset_t sigset;
handle_err:
	sigemptyset(&sigset);
	sigaddset(&sigset, sig);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	g_async_info.status = -1;
}

int v4_async_demo(int sg_fd, struct capacity16 *cap, int n_req)
{
	/* Buffers for data */
	uint8_t *data_buf = malloc((size_t) n_req * cap->lb_len);
	if (!data_buf) {
		perror("malloc");
		goto handle_err0;
	}

	/* SCSI-cmd array */
	uint8_t cdb_len = 16;
	uint32_t cdb_arr_len = n_req * cdb_len;
	uint8_t *cdb_arr = malloc(cdb_arr_len);
	if (!cdb_arr) {
		perror("malloc");
		goto handle_err1;
	}

	/* SG-v4 requests array */
	uint32_t req_arr_len = n_req * sizeof(struct sg_io_v4);
	struct sg_io_v4 *req_arr = malloc(req_arr_len);
	if (!req_arr) {
		perror("malloc");
		goto handle_err2;
	}

	for (int i = 0; i < n_req; i++) {
		/* Random block read16 */
		v4_init_hdr_read16(req_arr + i, cdb_arr + cdb_len * i,
				   rand_ranged(cap->lba_min, cap->lba_max),
				   1, data_buf + cap->lb_len * i, cap->lb_len);
		req_arr[i].usr_ptr = i;
	}

	/* Build sg v4 control object */
	struct sg_io_v4 ctl;
	memset(&ctl, 0, sizeof(ctl));
	ctl.guard		= 'Q';
	ctl.request		= (uintptr_t) cdb_arr;
	ctl.request_len		= cdb_arr_len;
	ctl.dout_xferp		= (uintptr_t) req_arr;
	ctl.dout_xfer_len	= req_arr_len;
	ctl.din_xferp		= (uintptr_t) req_arr;
	ctl.din_xfer_len	= req_arr_len;
	ctl.flags		= SGV4_FLAG_MULTIPLE_REQS | SGV4_FLAG_IMMED;

	/* Set handler, enable async */
	int signum = SIGRTMIN + 1;
	struct sigaction async_act = { .sa_handler = async_handler };
	if (sigaction(signum, &async_act, NULL) < 0) {
		perror("sigaction");
		goto handle_err3;
	}
	g_async_info.sg_fd	= sg_fd;
	g_async_info.cap	= cap;
	g_async_info.ctl	= &ctl;
	g_async_info.status	= 0;

	if (fd_enable_async_rt(sg_fd, signum) < 0)
		goto handle_err3;

	/* Send n_req read16 requests */
	int ret = ioctl(sg_fd, SG_IOSUBMIT, &ctl);
	if (ret < 0 || (errno = ctl.spare_out)) {
		perror("ioctl");
		goto handle_err3;
	}

	while (1) {
		if (g_async_info.status < 0) /* Declared volatile */
			goto handle_err3;
	}

	return 0;

handle_err3:
	free(req_arr);
handle_err2:
	free(cdb_arr);
handle_err1:
	free(data_buf);
handle_err0:
	return -1;
}


int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "/dev/... path expected\n");
		exit(EXIT_FAILURE);
	}

	int sg_fd = open(argv[1], O_RDWR);
	if (sg_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	struct capacity16 cap = { };
	if (v4_read_capacity16(sg_fd, &cap) < 0)
		exit(EXIT_FAILURE);

	dump_capacity16(&cap);

	if (v4_async_demo(sg_fd, &cap, 64) < 0)
		exit(EXIT_FAILURE);

	close(sg_fd);
	exit(EXIT_SUCCESS);
}
