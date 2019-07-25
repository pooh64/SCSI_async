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
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <byteswap.h>

#define printf_log(__fmt, ...)					\
	do {							\
		fprintf(stderr, "%s:%d:", __FILE__, __LINE__);	\
		fprintf(stderr, __fmt, ##__VA_ARGS__);		\
	} while(0)

int test_read_capacity16(char *path)
{
	uint8_t cdb[16] = { };
	uint8_t data[32] = { };
	cdb[0] = 0x9e;
	cdb[1] = 0x10;
	*((uint32_t*) &cdb[10]) = bswap_32(sizeof(data));

	struct sg_io_hdr hdr = {
		.interface_id		= 'S',
		.dxfer_direction	= SG_DXFER_FROM_DEV,
		.cmd_len		= sizeof(cdb),
		.mx_sb_len		= 64,
		.iovec_count		= 0,
		.dxfer_len		= sizeof(data),
		.dxferp			= data,
		.cmdp			= cdb,
		.sbp			= 0,
		.timeout		= 0,
		.flags			= 0,
		.pack_id		= 0,
		.usr_ptr		= 0,
		.status			= 0,
		.masked_status		= 0,
		.msg_status		= 0,
		.sb_len_wr		= 0,
		.host_status		= 0,
		.driver_status		= 0,
		.resid			= 0,
		.duration		= 0,
		.info			= 0
	};

	int sg_fd = open(path, O_RDWR);
	if (sg_fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (ioctl(sg_fd, SG_IO, &hdr) < 0) {
		perror("ioctl");
		exit(EXIT_FAILURE);
	}
	close(sg_fd);

	uint64_t lba_max = bswap_64(*((uint64_t*) &data[0]));
	uint32_t lb_len  = bswap_32(*((uint32_t*) &data[8]));
	uint8_t  p_type  = data[12] & (uint8_t) 0b00001110;
	uint8_t  prot_en = data[12] & (uint8_t) 1;
	uint32_t lba_min = data[14] & 0b00111111 << 8 + data[15];
	uint64_t dev_size = lb_len * (lba_max - lba_min);

	printf_log("lb_len = %lu\nlba_min = %lu\nlba_max = %lu\n"
		   "prot_en = %lu\np_type = %lu\ndev_size = %lu\n",
		   lb_len, lba_min, lba_max, prot_en, p_type, dev_size);

	return 0;
}

int test_single_read16(char *path)
{
	uint64_t lba = 0;
	uint32_t tr_len = 1;
	uint8_t gr_n = 0;
	uint32_t lb_len = 512;

	uint32_t buf_len = 512;
	assert(buf_len >= tr_len * lb_len);
	uint8_t *buf = malloc(buf_len);
	if (!buf) {
		perror("malloc");
		goto handle_err0;
	}
	memset(buf, 0, buf_len);

	uint8_t cdb[16] = { };
	cdb[0] = 0x88;
	cdb[1] = (uint8_t) 0b01100000;
	*((uint64_t*) &cdb[2])  = bswap_64(lba);
	*((uint32_t*) &cdb[10]) = bswap_32(tr_len);
	cdb[14] = gr_n;

	struct sg_io_v4 hdr_v4 = {
		.guard			= 'Q',	/* v4 */
		.protocol		= 0,	/* SCSI */
		.subprotocol		= 0,	/* SCSI SPC */
		.request_len		= sizeof(cdb),
		.request		= (uintptr_t) cdb,
		.request_tag		= 0,
		.request_attr		= 0,	/* unused */
		.request_priority	= 0,	/* unused */
		.request_extra		= 0,
		.max_response_len	= 0,
		.response		= 0,
		.dout_iovec_count	= 0,
		.dout_xfer_len		= 0,
		.din_iovec_count	= 0,
		.din_xfer_len		= buf_len,
		.dout_xferp		= 0,
		.din_xferp		= (uintptr_t) buf,
		.timeout		= 0,	/* default value */
		.flags			= 0,
		.usr_ptr		= 0,
		.spare_in		= 0,	/* unused */
		.driver_status		= 0,	/* output */
		.transport_status	= 0,	/* output */
		.device_status		= 0,	/* output */
		.retry_delay		= 0,	/* unused */
		.info			= 0,	/* output */
		.duration		= 0,	/* output */
		.response_len		= 0,	/* output */
		.din_resid		= 0,	/* output */
		.dout_resid		= 0,	/* output */
		.generated_tag		= 0,	/* output */
		.spare_out		= 0	/* errno */
	};

	int sg_fd = open(path, O_RDWR);
	if (sg_fd < 0) {
		perror("open");
		goto handle_err1;
	}

	if (ioctl(sg_fd, SG_IO, &hdr_v4) < 0) {
		perror("ioctl");
		goto handle_err2;
	}
	close(sg_fd);
	free(buf);
	return 0;

handle_err2:
	close(sg_fd);
handle_err1:
	free(buf);
handle_err0:
	return -1;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "sg path expected\n");
		exit(EXIT_FAILURE);
	}
	printf_log("--- Testing READ CAPACITY (16) ---\n");
	test_read_capacity16(argv[1]);
	printf_log("--- Tesitng READ (16) ---\n");
	test_single_read16(argv[1]);
	return 0;
}
