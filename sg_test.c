#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include <scsi/sg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <byteswap.h>

#define printf_log(__fmt, ...)					\
	do {							\
		fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);	\
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
		.dxfer_len		= sizeof(data),
		.dxferp			= data,
		.cmdp			= cdb,
	};

	int sg_fd = open(path, O_RDWR);
	if (sg_fd < 0) {
		perror("open");
		return -1;
	}

	if (ioctl(sg_fd, SG_IO, &hdr) < 0) {
		perror("ioctl");
		close(sg_fd);
		return -1;
	}
	close(sg_fd);

	uint64_t lba_max = bswap_64(*((uint64_t*) &data[0]));
	uint32_t lb_len  = bswap_32(*((uint32_t*) &data[8]));
	uint8_t  p_type  = data[12] & (uint8_t) 0b00001110;
	uint8_t  prot_en = data[12] & (uint8_t) 1;
	uint32_t lba_min = (data[14] & 0b00111111) << 8 + data[15];
	uint64_t dev_size = lb_len * (lba_max - lba_min);

	printf_log("lb_len = %lu\nlba_min = %lu\nlba_max = %lu\n"
		   "prot_en = %lu\np_type = %lu\ndev_size = %lu\n",
		   lb_len, lba_min, lba_max, prot_en, p_type, dev_size);

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "/dev/sg path expected\n");
		exit(EXIT_FAILURE);
	}
	printf_log("--- Testing READ CAPACITY (16) ---\n");
	test_read_capacity16(argv[1]);
	exit(EXIT_SUCCESS);
}
