// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020, Intel Corporation
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>

#include "intel_fcs-ioctl.h"
#include "intel_fcs_structs.h"
#include "sha2.h"

#include "tools/fit_common.h"
#include "tools/imagetool.h"

#define MAX_CERT_SIZE		(4 * 1024)

#define SEARCH_CHUNKSIZE	sizeof(struct fcs_hps_vab_certificate_header)
#define CERT_LEN_PARAM_SZ	sizeof(uint32_t)

#define VAB_CERT_MAGIC_OFFSET	(offsetof \
				 (struct fcs_hps_vab_certificate_header, d))

#define VAB_CERT_FIT_SHA384_OFFSET	(offsetof \
					 (struct fcs_hps_vab_certificate_data, \
					  fcs_sha384[0]))

#define NOT_ALLOWED_UNDER_SECURITY_SETTINGS	0x85

const char *dev = "/dev/fcs";

/*
 * option_ops - translate the long options to short options
 *
 * The main commands are uppercase. The extras are lowercase.
 *
 */
static const struct option opts[] = {
	{"validate", required_argument, NULL, 'V'},
	{"type", required_argument, NULL, 't'},
	{"counter_set", required_argument, NULL, 'C'},
	{"get_provision_data", required_argument, NULL, 'G'},
	{"print", no_argument, NULL, 'p'},
	{"cache", required_argument, NULL, 'c'},
	{"aes_encrypt", no_argument, NULL, 'E'},
	{"aes_decrypt", no_argument, NULL, 'D'},
	{"out_filename", required_argument, NULL, 'o'},
	{"in_filename", required_argument, NULL, 'i'},
	{"own_hash", required_argument, NULL, 'r'},
	{"own_id", required_argument, NULL, 'd'},
	{"random", required_argument, NULL, 'R'},
	{"verbose", required_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0}
};

/*
 * fcs_client_usage() - show the usage of client application
 *
 * This function doesn't have a return value.
 *
 */
static void fcs_client_usage(void)
{
	printf("\n--- FPGA Crypto Services Client app usage ---\n\n");
	printf("%-32s  %s", "-V|--validate <filename> -t|--type <HPS_image(0)|bitstream(1)>\n",
	       "\tValidate an HPS or bitstream image\n\n");
	printf("%-32s  %s %s", "-C|--counter_set <signed_file> -c|--cache <0|1>\n",
	       "\tSet the counter value - requires signed file as parameter and\n",
	       "\twrite to cache instead of fuses if --cache set to 1\n\n");
	printf("%-32s  %s", "-G|--get_provision_data <output_filename> -p|--print\n",
	       "\tGet the provisioning data from SDM\n\n");
	printf("%-32s  %s %s", "-E|--aes_encrypt -i <input_filename> -o <output_filename> -r <owner_id> -d <ASOI>\n",
	       "\tAES Encrypt a buffer of up to 32K-96 bytes - requires owner_id file (8 bytes)\n",
	       "\tand Applications Specific Object Info(unique 2 byte identifier)\n\n");
	printf("%-32s  %s", "-D|--aes_decrypt -i <input_filename> -o|--out_filename <output_filename>\n",
	       "\tAES Decrypt a buffer of up to 32K-96 bytes\n\n");
	printf("%-32s  %s", "-R|--random <output_filename>\n",
	       "\tReturn up to a 32-byte of random data\n\n");
	printf("%-32s  %s", "-v|--verbose",
	       "Verbose printout\n\n");
	printf("%-32s  %s", "-h|--help", "Show usage message\n");
	printf("\n");
}

/*
 * fcs_send_ioctl_request
 * @dev_ioct: Combined structure for IOCTL calls
 * @command: Command to send
 *
 * Return: 0 on success, or error on failure
 *
 */
static int fcs_send_ioctl_request(struct intel_fcs_dev_ioctl *dev_ioctl,
				  enum intel_fcs_command_code command)
{
	int fd, ret = 0;

	/* FCS service request */
	fd = open(dev, O_RDWR | O_EXCL);
	if (fd < 0) {
		fprintf(stderr, "can't open %s:  %s\n", dev, strerror(errno));
		return -1;
	}

	if (ioctl(fd, command, dev_ioctl) < 0) {
		fprintf(stderr, "ioctl[%d] failed:  %s\n",
			errno, strerror(errno));
		ret = -1;
	}

	close(fd);

	return ret;
}

/*
 * get_img_size() - Get Image filesize
 * @img_buf: Image buffer
 * @img_buf_sz: size of the image buffer & certificate &
 *	certificate length word.
 *
 * Return: 0 on failure, size of image (w/o cert) on success
 *
 */
static size_t get_img_size(const uint8_t *img_buf, size_t img_buf_sz)
{
	const uint8_t *img_buf_end = img_buf + img_buf_sz;
	const uint32_t cert_sz = *(uint32_t *)(img_buf_end - CERT_LEN_PARAM_SZ);
	const uint8_t *p = img_buf_end - cert_sz - CERT_LEN_PARAM_SZ;

	/* Ensure p is pointing within the hps_buf */
	if (p < img_buf || p > (img_buf_end - CERT_LEN_PARAM_SZ))
		return 0;

	if (*(uint32_t *)p == SDM_CERT_MAGIC_NUM)
		return (size_t)(p - img_buf);

	return 0;
}

/*
 * calc_fit_image_hash() - Generate HASH 384 from the FIT
 * @hps_buf: FIT buffer for hashing
 * @hash_bufsize: size of the FIT buffer
 * @hash_buf: buffer for holding SHA384
 *
 * Return: 0 on success of hash calculation, or error on failure
 *
 */
static int calc_fit_image_hash(const uint8_t *hps_buf, size_t hps_bufsize,
			       uint8_t *hash_buf)
{
	struct sha384_ctx sha384;

	if (!hps_bufsize)
		return -1;

	/* compute the FIT hash */
	sha384_init(&sha384);
	sha384_update(&sha384, hps_bufsize, hps_buf);
	sha384_digest(&sha384, SHA384_SZ, hash_buf);

	return 0;
}

/*
 * dump_hash() - dump the hash bytes
 * @buf: buffer holding hash bytes
 * @size: number of bytes to print
 *
 */
static void dump_hash(uint8_t *buf, size_t size)
{
	int i, j;

	for (j = 0; j < size; j += 8) {
		printf("%04x: ", j);
		for (i = 0; i < 8; i++)
			printf("%02x ", buf[j + i]);
		printf("\n");
	}
}

/*
 * verify_hash() - verify the certificate hash matches the calculated
 * @pcert: vab certificate header
 * @hash: calculated hash
 * @hashsz: number of bytes to compare
 * @verbose: verbosity of output (true = more output)
 *
 */
static int verify_hash(struct fcs_hps_vab_certificate_header *pcert,
		       uint8_t *hash, size_t hashsz, bool verbose)
{
	/* Check the magic # to make sure this is valid*/
	if (pcert->cert_magic_num != SDM_CERT_MAGIC_NUM) {
		fprintf(stderr, "Invalid Certificate Found :\n");
		return -1;
	}
	if (verbose) {
		/* Print the hash result */
		printf("Computed Hash\n");
		dump_hash(hash, hashsz);
		/* Print the hash in certresult */
		printf("Certificate Hash\n");
		dump_hash(&pcert->d.fcs_sha384[0], sizeof(pcert->d.fcs_sha384));
	}

	if (memcmp(hash, &pcert->d.fcs_sha384[0], hashsz)) {
		fprintf(stderr, "Hashes don't match, Exiting.\n");
		return -1;
	}
	return 0;
}

/*
 * fcs_validate_hps_image_buf() - authorize HPS image
 * @data: the component data to validate
 * @csize: size of data to validate.
 * @verbose: verbosity of output (true = more output)
 *
 * Return: 0 on authorization success, or error on failure
 *
 */
static int fcs_validate_hps_image_buf(const void *cdata, size_t csize,
				      bool verbose)
{
	struct fcs_hps_vab_certificate_header *pcert;
	struct intel_fcs_dev_ioctl *dev_ioctl;
	const uint8_t *data = cdata;
	uint8_t hash[SHA512_DIGEST_SIZE];
	size_t certsz, datasz;
	int status;
	int ret;

	dev_ioctl = (struct intel_fcs_dev_ioctl *)
			malloc(sizeof(struct intel_fcs_dev_ioctl));
	if (!dev_ioctl) {
		fprintf(stderr, "can't malloc %s:  %s\n", dev, strerror(errno));
		return -1;
	}

	/* Find the actual size of data without compact certificate */
	datasz = get_img_size(data, csize);
	if (!datasz) {
		fprintf(stderr, "Unable to find compact certficate\n");
		free(dev_ioctl);
		return -1;
	}

	/* compute the data hash */
	printf("%s[%d] perform Hash Calculation\n", __func__, __LINE__);
	calc_fit_image_hash(data, datasz, hash);
	/* Setup certificate pointer */
	pcert = (struct fcs_hps_vab_certificate_header *)&data[datasz];
	ret = verify_hash(pcert, &hash[0], SHA384_SZ, verbose);
	if (ret) {
		free(dev_ioctl);
		return -1;
	}
	if (verbose)
		printf("Hash matches so sending to SDM...\n");
	certsz = csize - datasz;
	if (verbose)
		printf("VAB Certificate size is %ld.\n", certsz);
	/* Passed hash comparison so continue */
	dev_ioctl->com_paras.c_request.size = certsz;
	dev_ioctl->com_paras.c_request.addr = pcert;
	dev_ioctl->com_paras.c_request.test.test_word = INTEL_FCS_NO_TEST;
	dev_ioctl->com_paras.c_request.c_status = INTEL_CERT_STATUS_NONE;
	dev_ioctl->status = -1;
	if (verbose)
		printf("ioctl size=%d, address=0x%p\n",
			dev_ioctl->com_paras.c_request.size, pcert);
	/* HPS Image validation uses the certificate command */
	fcs_send_ioctl_request(dev_ioctl, INTEL_FCS_DEV_SEND_CERTIFICATE);

	printf("ioctl return status=0x%x size=%d\n",
		dev_ioctl->status, dev_ioctl->com_paras.s_request.size);

	status = dev_ioctl->status;
	if (status)
		printf("Certificate Error: 0x%X\n",
			dev_ioctl->com_paras.c_request.c_status);

	memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
	free(dev_ioctl);

	return status;
}

/*
 * fcs_validate_fit_components() - Validate the components of image
 * @fit: Pointer to FIT image.
 * @verbose: verbosity of output (true = more output)
 *
 * Return: 0 on success, or error on failure
 *
 */
static int fcs_validate_fit_components(void *fit, bool verbose)
{
	int ndepth, noffset, count, images_noffset, status;

	images_noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images_noffset < 0) {
		printf("Can't find images parent node '%s' (%s)\n",
		       FIT_IMAGES_PATH, fdt_strerror(images_noffset));
		return -1;
	}

	/* Process its subnodes, extract the desired component from image */
	for (ndepth = 0, count = 0,
		noffset = fdt_next_node(fit, images_noffset, &ndepth);
		(noffset >= 0) && (ndepth > 0);
		noffset = fdt_next_node(fit, noffset, &ndepth)) {
		if (ndepth == 1) {
			/*
			 * Direct child node of the images parent node,
			 * i.e. component image node.
			 */
			const void *comp_data;
			size_t comp_sz;

			status = fit_image_get_data_and_size(fit, noffset,
							     &comp_data,
							     &comp_sz);
			if (verbose && !status)
				printf("%s[%d] Subcomponent %d in FIT: size=%lu[0x%lx]\n",
				       __func__, __LINE__, count + 1, comp_sz, comp_sz);
			if (status) {
				fprintf(stderr, "Problem getting component data\n");
				return -1;
			}
			status = fcs_validate_hps_image_buf(comp_data, comp_sz, verbose);

			if (status &&
			    (status != NOT_ALLOWED_UNDER_SECURITY_SETTINGS)) {
				fprintf(stderr, "Error validating component data\n");
				return -1;
			}
			count++;
		}
	}
	if (verbose)
		printf("%s[%d] Successfully validated %d subcomponents in FIT\n",
		       __func__, __LINE__, count);
	return 0;
}

/*
 * fcs_validate_request() - authorize HPS image or bitstream
 * @filename: the filename to check.
 * @type: type of file (0 for HPS, 1 for bitstream)
 * @verbose: verbosity of output (true = more output)
 *
 * Return: 0 on authorization success, or error on failure
 *
 */
static int fcs_validate_request(char *filename, int type, bool verbose)
{
	size_t filesize, sz;
	struct stat st;
	int status;
	FILE *fp;

	fp = fopen(filename, "rbx");
	if (!fp) {
		fprintf(stderr, "Unable to open file %s:  %s\n",
			filename, strerror(errno));
		return -1;
	}

	/* Get the file statistics */
	if (fstat(fileno(fp), &st)) {
		fclose(fp);
		fprintf(stderr, "Unable to open file %s:  %s\n",
			filename, strerror(errno));
		return -1;
	}

	/* Find the filesize */
	filesize = st.st_size;
	if (verbose)
		printf("%s[%d] filesize=%ld\n", __func__, __LINE__, filesize);

	/* In the case of HPS image, more processing is needed. */
	if (type == INTEL_FCS_IMAGE_HPS) {
		struct image_tool_params params;
		uint8_t *hps_buff;

		/* Allocate a buffer that is the file size */
		hps_buff = malloc(filesize);
		if (!hps_buff) {
			fprintf(stderr, "can't alloc buffer for %s:  %s\n",
				filename, strerror(errno));
			fclose(fp);
			return -1;
		}
		/* Set file handle to beginning of FIT image */
		fseek(fp, 0, SEEK_SET);
		/* Read the file into the buffer */
		sz = fread(hps_buff, 1, filesize, fp);
		fclose(fp);
		if (verbose)
			printf("%s[%d] sz=%ld, filesize=%ld\n",
				__func__, __LINE__, sz, filesize);
		if (sz != filesize) {
			fprintf(stderr, "Problem reading file into buffer %s: %s\n",
				filename, strerror(errno));
			memset(hps_buff, 0, filesize);
			free(hps_buff);
			return -1;
		}

		/* If this is a FIT image, parse each component, otherwise check image */
		params.type = IH_TYPE_FLATDT;
		if (fit_verify_header(hps_buff, filesize, &params)) {
			if (verbose)
				printf("%s[%d] Parsing Normal image\n", __func__, __LINE__);

			status = fcs_validate_hps_image_buf(hps_buff, filesize, verbose);
		} else {
			if (verbose)
				printf("%s[%d] Parsing FIT image\n", __func__, __LINE__);

			status = fcs_validate_fit_components(hps_buff, verbose);
		}
		memset(hps_buff, 0, filesize);
		free(hps_buff);
	} else {
		struct intel_fcs_dev_ioctl *dev_ioctl = (struct intel_fcs_dev_ioctl *)
				malloc(sizeof(struct intel_fcs_dev_ioctl));

		fclose(fp);
		if (!dev_ioctl) {
			fprintf(stderr, "can't malloc %s:  %s\n", dev, strerror(errno));
			return -1;
		}
		/* Fill in the structure for bitstream */
		dev_ioctl->com_paras.s_request.so_type = type;
		dev_ioctl->com_paras.s_request.size = filesize;
		dev_ioctl->com_paras.s_request.src = filename;
		dev_ioctl->status = -1;

		/* HPS Image validation uses the RECONFIG command */
		fcs_send_ioctl_request(dev_ioctl, INTEL_FCS_DEV_VALIDATION_REQUEST);

		printf("ioctl return status=0x%x size=%d\n",
			dev_ioctl->status, dev_ioctl->com_paras.s_request.size);

		status = dev_ioctl->status;
		memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
		free(dev_ioctl);
	}
	return status;
}

/*
 * fcs_service_counter_set() - set the counter
 * @filename: the filename containing the signed counter set request.
 * @test: indicates the cache ram should be used instead of fuses.
 *
 * Return: 0 on success, or error on failure
 */
static int fcs_service_counter_set(char *filename, int test)
{
	struct intel_fcs_dev_ioctl *dev_ioctl;
	size_t sz, filesize;
	struct stat st;
	void *buffer;
	FILE *file;
	int status;

	if (!filename) {
		fprintf(stderr, "Null filename:  %s\n", strerror(errno));
		return -1;
	}

	dev_ioctl = (struct intel_fcs_dev_ioctl *)
			malloc(sizeof(struct intel_fcs_dev_ioctl));
	if (!dev_ioctl) {
		fprintf(stderr, "can't malloc %s:  %s\n", dev, strerror(errno));
		return -1;
	}

	file = fopen(filename, "rbx");
	if (!file) {
		fprintf(stderr, "Unable to open file %s:  %s\n",
			filename, strerror(errno));
		free(dev_ioctl);
		return -1;
	}
	/* Get the file statistics */
	if (fstat(fileno(file), &st)) {
		fprintf(stderr, "Unable to open file %s:  %s\n",
			filename, strerror(errno));
		free(dev_ioctl);
		fclose(file);
		return -1;
	}
	/* Find the filesize */
	filesize = st.st_size;

	/* Allocate a buffer that is the certificate size */
	buffer = calloc(filesize, sizeof(uint8_t));
	if (!buffer) {
		fprintf(stderr, "can't calloc buffer for %s:  %s\n",
			filename, strerror(errno));
		free(dev_ioctl);
		fclose(file);
		return -1;
	}

	/* Read the file into the buffer */
	sz = fread(buffer, 1, filesize, file);
	if (sz != filesize) {
		fprintf(stderr, "Size mismatch reading data into buffer [%ld/%ld] %s:  %s\n",
			sz, filesize, filename, strerror(errno));
		memset(buffer, 0, filesize);
		free(buffer);
		free(dev_ioctl);
		fclose(file);
		return -1;
	}
	fclose(file);

	/* Fill in the structure */
	dev_ioctl->com_paras.c_request.addr = buffer;
	dev_ioctl->com_paras.c_request.size = filesize;
	dev_ioctl->com_paras.c_request.test.test_word = (test<<31);
	dev_ioctl->com_paras.c_request.c_status = INTEL_CERT_STATUS_NONE;
	dev_ioctl->status = -1;

	fcs_send_ioctl_request(dev_ioctl, INTEL_FCS_DEV_SEND_CERTIFICATE);

	printf("ioctl return status=%d\n", dev_ioctl->status);
	status = dev_ioctl->status;

	if (status)
		printf("Certificate Error: 0x%X\n",
			dev_ioctl->com_paras.c_request.c_status);

	memset(buffer, 0, filesize);
	free(buffer);
	memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
	free(dev_ioctl);

	return status;
}

/*
 * print_hash_data() - Print the passed in hash data.
 * @gpd: input pointer to the data to be parsed.
 * @pcntrs: Since parsing how many Hash arrays, return pointer to
 *	    where the counters data should start.
 *
 * Return: 0 on success, or error on failure
 */
static int print_hash_data(struct fcs_get_provision_data *gpd,
			   struct fcs_get_counters_data **pcntrs)
{
	int i;
	int number_of_hashes;

	number_of_hashes = gpd->header.num_hashes + 1;
	printf("number of hashes is %d\n", number_of_hashes);

	for (i = 0; i < number_of_hashes; i++) {
		uint32_t *p_cancel_status;
		uint8_t *p_hash;
		int hash_sz;

		if (gpd->header.type_hash == INTEL_FCS_HASH_SECP256) {
			hash_sz = sizeof(gpd->hash_256->owner_root_hash);
			p_hash = &gpd->hash_256[i].owner_root_hash[0];
			p_cancel_status = &gpd->hash_256[i].cancel_status;
		} else if (gpd->header.type_hash == INTEL_FCS_HASH_SECP384R1) {
			hash_sz = sizeof(gpd->hash_384->owner_root_hash);
			p_hash = &gpd->hash_384[i].owner_root_hash[0];
			p_cancel_status = &gpd->hash_384[i].cancel_status;
		} else {
			return -1;
		}

		dump_hash(p_hash, hash_sz);

		printf("KCS[%d]: 0x%X\n", i, *p_cancel_status);
	}
	/* Set the counter pointer to the end of data */
	if (gpd->header.type_hash == INTEL_FCS_HASH_SECP256)
		*pcntrs = (struct fcs_get_counters_data *)
			&(gpd->hash_256[number_of_hashes]);
	else if (gpd->header.type_hash == INTEL_FCS_HASH_SECP384R1)
		*pcntrs = (struct fcs_get_counters_data *)
			&(gpd->hash_384[number_of_hashes]);

	return 0;
}

/*
 * fcs_service_get_provision_data() - get the provisioning data
 * @filename: the filename to save provisioning data into.
 * @prnt: print the results to console
 *
 * Return: 0 on success, or error on failure
 */
static int fcs_service_get_provision_data(char *filename, int prnt)
{
	struct intel_fcs_dev_ioctl *dev_ioctl;
	size_t filesize;
	void *buffer;
	FILE *file;
	int status;

	if (!filename) {
		fprintf(stderr, "NULL filename:  %s\n", strerror(errno));
		return -1;
	}

	dev_ioctl = (struct intel_fcs_dev_ioctl *)
			malloc(sizeof(struct intel_fcs_dev_ioctl));
	if (!dev_ioctl) {
		fprintf(stderr, "can't malloc %s:  %s\n", dev, strerror(errno));
		return -1;
	}

	/* Allocate a buffer and read the file into the buffer */
	buffer = malloc(sizeof(struct fcs_get_provision_data));
	if (!buffer) {
		fprintf(stderr, "can't malloc buffer for provision data:  %s\n",
			strerror(errno));
		free(dev_ioctl);
		return -1;
	}

	/* Fill in the structure */
	dev_ioctl->com_paras.gp_data.addr = buffer;
	dev_ioctl->com_paras.gp_data.size = sizeof(struct fcs_get_provision_data);
	dev_ioctl->status = -1;

	fcs_send_ioctl_request(dev_ioctl, INTEL_FCS_DEV_GET_PROVISION_DATA);

	printf("ioctl return status=%d\n", dev_ioctl->status);

	/* Printout in human readable form if needed */
	if (prnt) {
		struct fcs_get_provision_data *provision = buffer;
		struct fcs_get_provision_header *hdr = buffer;
		struct fcs_get_counters_data *pcntrs = NULL;
		char no_hash_str[] = "None";
		char type256_hash_str[] = "secp256r1";
		char type384_hash_str[] = "secp384r1";
		int number_hashes = hdr->num_hashes + 1;
		char *type_hash_str = no_hash_str;

		printf("W0:Provision Status Code: 0x%X\n",
			hdr->provision_status);
		printf("W1:Key Cancellation Status: 0x%X\n",
			hdr->intel_key_status);
		printf("W2:Co-Sign Status:          %d\n",
			hdr->co_sign_status);
		printf("W2:RootHash0 Cancel Status: %d\n",
			hdr->root_hash_status & 0x1);
		printf("W2:RootHash1 Cancel Status: %d\n",
			hdr->root_hash_status & 0x2);
		printf("W2:RootHash2 Cancel Status: %d\n",
			hdr->root_hash_status & 0x4);
		printf("W2:Number of Hashes:        %d\n", number_hashes);
		if (hdr->type_hash == INTEL_FCS_HASH_SECP256)
			type_hash_str = type256_hash_str;
		else if (hdr->type_hash == INTEL_FCS_HASH_SECP384R1)
			type_hash_str = type384_hash_str;

		printf("W2:Type of Hash:            %s\n", type_hash_str);
		/* Print the hash data */
		print_hash_data(provision, &pcntrs);
		/* Print the counters here - variable */
		if (pcntrs) {
			printf("C1:Big Counter Base:   0x%X\n",
				pcntrs->big_cntr_base_value);
			printf("C1:Big Counter Value:  0x%X\n",
				pcntrs->big_cntr_count_value);
			printf("C2:SVN Counter Value3: 0x%X\n",
				pcntrs->svn_count_val3);
			printf("C2:SVN Counter Value2: 0x%X\n",
				pcntrs->svn_count_val2);
			printf("C2:SVN Counter Value1: 0x%X\n",
				pcntrs->svn_count_val1);
			printf("C2:SVN Counter Value0: 0x%X\n",
				pcntrs->svn_count_val0);
		}
	}

	file = fopen(filename, "wbx");
	if (!file) {
		fprintf(stderr, "Unable to open file %s:  %s\n",
			filename, strerror(errno));
		memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
		free(dev_ioctl);
		memset(buffer, 0, sizeof(struct fcs_get_provision_data));
		free(buffer);
		return -1;
	}
	filesize = fwrite(buffer, 1, dev_ioctl->com_paras.gp_data.size, file);
	if (filesize != dev_ioctl->com_paras.gp_data.size)
		fprintf(stderr, "Write count %ld did not match returned count %d\n",
			filesize, dev_ioctl->com_paras.gp_data.size);
	fclose(file);

	status = dev_ioctl->status;

	memset(buffer, 0, sizeof(struct fcs_get_provision_data));
	free(buffer);
	memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
	free(dev_ioctl);

	return status;
}

/*
 * dump_aes_hdr() - dump the AES Header
 * @aes_hdr: AES Header to dump
 *
 */
static void dump_aes_hdr(struct fcs_aes_crypt_header *aes_hdr)
{
	int i;

	printf("Magic Number: 0x%X\n", aes_hdr->magic_number);
	printf("Data Length (w/ padding): %d\n", aes_hdr->data_len);
	printf("Pad: %d\n", aes_hdr->pad);
	printf("SRKI: %d\n", aes_hdr->srk_indx);
	printf("ASOI: %d\n", aes_hdr->app_spec_obj_info);
	printf("Owner ID: ");
	for (i = 0; i < sizeof(aes_hdr->owner_id); i++)
		printf("%02x ", aes_hdr->owner_id[i]);

	printf("\n");
	printf("Header Padding: 0x%X\n", aes_hdr->hdr_pad);
	printf("IV field: ");
	for (i = 0; i < sizeof(aes_hdr->iv_field); i++)
		printf("%02x ", aes_hdr->iv_field[i]);
	printf("\n");
}

/*
 * fcs_sdos_encrypt() - encrypt data
 * @filename: Filename holding data to encrypt
 * @outfilename: Resulting filename holding encrypted data
 * @identier: Binary data identifier
 * @own: Owner key
 * @verbose: verbosity of output (true = more output)
 *
 * Return: 0 on success, or error on failure
 */
static int fcs_sdos_encrypt(char *filename, char *outfilename,
		     int identifier, uint64_t own, bool verbose)
{
	struct intel_fcs_dev_ioctl *dev_ioctl;
	struct fcs_aes_crypt_header *aes_hdr;
	uint8_t *in_buf, *out_buf;
	size_t filesize, sz;
	int calc, pad = 0;
	struct stat st;
	int status, i;
	FILE *fp;

	/* Open input binary file */
	fp = fopen(filename, "rbx");
	if (!fp) {
		fprintf(stderr, "can't open %s for reading: %s\n",
			filename, strerror(errno));
		return -1;
	}
	/* Get the file statistics */
	if (fstat(fileno(fp), &st)) {
		fclose(fp);
		fprintf(stderr, "Unable to open file %s:  %s\n",
			filename, strerror(errno));
		return -1;
	}

	/* Find the filesize */
	filesize = st.st_size;
	if (verbose)
		printf("%s[%d] filesize=%ld\n", __func__, __LINE__, filesize);

	/* Make sure the data is less than 32K - 96 bytes */
	if (filesize > SDOS_PLAINDATA_MAX_SZ ||
	    filesize < SDOS_PLAINDATA_MIN_SZ) {
		fprintf(stderr, "Invalid filesize %ld. Must be > 16 and <= 32,672\n",
			filesize);
		fclose(fp);
		return -1;
	}

	/* Allocate a buffer for the input data */
	in_buf = calloc(SDOS_DECRYPTED_MAX_SZ, sizeof(uint8_t));
	if (!in_buf) {
		fprintf(stderr, "can't calloc buffer for %s:  %s\n",
			filename, strerror(errno));
		fclose(fp);
		return -1;
	}
	/* Allocate a buffer for the output data */
	out_buf = calloc(SDOS_ENCRYPTED_MAX_SZ, sizeof(uint8_t));
	if (!out_buf) {
		fprintf(stderr, "can't calloc buffer for %s:  %s\n",
			outfilename, strerror(errno));
		fclose(fp);
		free(in_buf);
		return -1;
	}

	/* Read the file into the buffer (after the header) */
	sz = fread(in_buf + sizeof(struct fcs_aes_crypt_header), 1, filesize, fp);
	fclose(fp);
	if (sz != filesize) {
		fprintf(stderr, "can't read entire file %s\n", filename);
		memset(in_buf, 0, SDOS_DECRYPTED_MAX_SZ);
		free(in_buf);
		free(out_buf);
		return -1;
	}

	/* Initialize the header */
	aes_hdr = (struct fcs_aes_crypt_header *)in_buf;
	aes_hdr->magic_number = 0xACBDBDED;
	calc = filesize % 16;
	if (calc)
		pad = 16 - calc;
	aes_hdr->data_len = filesize + pad;
	aes_hdr->pad = pad;
	aes_hdr->srk_indx = 0;
	aes_hdr->app_spec_obj_info = identifier;
	for (i = 0; i < sizeof(aes_hdr->owner_id); i++) {
		aes_hdr->owner_id[i] = (uint8_t)own;
		own >>= 8;
	}
	aes_hdr->hdr_pad = 0x01020304;
	/* to initialize for the generated IV */
	for (i = 0; i < sizeof(aes_hdr->iv_field); i++)
		aes_hdr->iv_field[i] = 0;

	if (verbose)
		dump_aes_hdr(aes_hdr);

	dev_ioctl = (struct intel_fcs_dev_ioctl *)
			malloc(sizeof(struct intel_fcs_dev_ioctl));
	if (!dev_ioctl) {
		fprintf(stderr, "can't malloc %s:  %s\n", dev, strerror(errno));
		memset(in_buf, 0, SDOS_DECRYPTED_MAX_SZ);
		free(in_buf);
		free(out_buf);
		return -1;
	}

	/* Fill in the dev_ioctl structure */
	dev_ioctl->com_paras.d_encryption.src = in_buf;
	dev_ioctl->com_paras.d_encryption.src_size = filesize + pad +
					 sizeof(struct fcs_aes_crypt_header);
	dev_ioctl->com_paras.d_encryption.dst = out_buf;
	dev_ioctl->com_paras.d_encryption.dst_size = SDOS_ENCRYPTED_MAX_SZ;
	dev_ioctl->status = -1;

	fcs_send_ioctl_request(dev_ioctl, INTEL_FCS_DEV_DATA_ENCRYPTION);

	status = dev_ioctl->status;
	printf("ioctl return status=%d\n", dev_ioctl->status);

	if (status) {
		memset(in_buf, 0, SDOS_DECRYPTED_MAX_SZ);
		memset(out_buf, 0, SDOS_ENCRYPTED_MAX_SZ);
		free(in_buf);
		free(out_buf);
		memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
		free(dev_ioctl);
		return status;
	}

	/* Save result in binary file */
	fp = fopen(outfilename, "wbx");
	if (!fp) {
		fprintf(stderr, "can't open %s for writing: %s\n",
			outfilename, strerror(errno));
		memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
		free(dev_ioctl);
		memset(in_buf, 0, SDOS_DECRYPTED_MAX_SZ);
		memset(out_buf, 0, SDOS_ENCRYPTED_MAX_SZ);
		free(in_buf);
		free(out_buf);
		return -1;
	}

	if (verbose) {
		printf("Save encrypted data to %s\n", outfilename);
		printf("Saving %d [0x%X] bytes\n",
			dev_ioctl->com_paras.d_encryption.dst_size,
			dev_ioctl->com_paras.d_encryption.dst_size);
	}

	fwrite(dev_ioctl->com_paras.d_encryption.dst,
	       dev_ioctl->com_paras.d_encryption.dst_size, 1, fp);

	fclose(fp);
	memset(in_buf, 0, SDOS_DECRYPTED_MAX_SZ);
	memset(out_buf, 0, SDOS_ENCRYPTED_MAX_SZ);
	free(in_buf);
	free(out_buf);
	memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
	free(dev_ioctl);

	return status;
}

/*
 * fcs_sdos_decrypt() - decrypt data
 * @filename: Filename holding encrypted data to decrypt
 * @outfilename: Resulting filename holding decrypted data
 * @verbose: verbosity of output (true = more output)
 *
 * Return: 0 on success, or error on failure
 */
static int fcs_sdos_decrypt(char *filename, char *outfilename, bool verbose)
{
	struct intel_fcs_dev_ioctl *dev_ioctl;
	struct fcs_aes_crypt_header *aes_hdr;
	uint8_t *in_buf, *out_buf;
	size_t filesize, sz;
	struct stat st;
	int status;
	FILE *fp;

	/* Open input binary file */
	fp = fopen(filename, "rbx");
	if (!fp) {
		fprintf(stderr, "can't open %s for reading: %s\n",
			filename, strerror(errno));
		return -1;
	}

	/* Get the file statistics */
	if (fstat(fileno(fp), &st)) {
		fclose(fp);
		fprintf(stderr, "Unable to open file %s:  %s\n",
			filename, strerror(errno));
		return -1;
	}

	/* Find the filesize */
	filesize = st.st_size;
	if (verbose)
		printf("%s[%d] filesize=%ld\n", __func__, __LINE__, filesize);

	/* Make sure the data is less than 32K - 96 bytes */
	if (filesize > SDOS_ENCRYPTED_MAX_SZ ||
	    filesize < SDOS_ENCRYPTED_MIN_SZ) {
		fprintf(stderr, "Invalid filesize %ld. Must be > 16 and <= 32,672\n",
			filesize);
		fclose(fp);
		return -1;
	}

	/* Allocate a buffer for the input data */
	in_buf = calloc(SDOS_ENCRYPTED_MAX_SZ, sizeof(uint8_t));
	if (!in_buf) {
		fprintf(stderr, "can't calloc buffer for %s:  %s\n",
			filename, strerror(errno));
		fclose(fp);
		return -1;
	}
	/* Allocate a buffer for the output data */
	out_buf = calloc(SDOS_DECRYPTED_MAX_SZ, sizeof(uint8_t));
	if (!out_buf) {
		fprintf(stderr, "can't calloc buffer for %s:  %s\n",
			outfilename, strerror(errno));
		fclose(fp);
		free(in_buf);
		return -1;
	}

	/* Read the file into the buffer (input file includes the header) */
	sz = fread(in_buf, 1, filesize, fp);
	fclose(fp);
	if (sz != filesize) {
		fprintf(stderr, "Size mismatch reading data into buffer [%ld/%ld] %s:  %s\n",
			sz, filesize, filename, strerror(errno));
		memset(in_buf, 0, SDOS_ENCRYPTED_MAX_SZ);
		free(in_buf);
		free(out_buf);
		return -1;
	}

	dev_ioctl = (struct intel_fcs_dev_ioctl *)
			malloc(sizeof(struct intel_fcs_dev_ioctl));
	if (!dev_ioctl) {
		fprintf(stderr, "can't malloc %s:  %s\n", dev, strerror(errno));
		memset(in_buf, 0, SDOS_ENCRYPTED_MAX_SZ);
		free(in_buf);
		free(out_buf);
		return -1;
	}

	/* Fill in the dev_ioctl structure */
	dev_ioctl->com_paras.d_decryption.src = in_buf;
	dev_ioctl->com_paras.d_decryption.src_size = filesize;
	dev_ioctl->com_paras.d_decryption.dst = out_buf;
	dev_ioctl->com_paras.d_decryption.dst_size = SDOS_DECRYPTED_MAX_SZ;
	dev_ioctl->status = -1;

	fcs_send_ioctl_request(dev_ioctl, INTEL_FCS_DEV_DATA_DECRYPTION);

	status = dev_ioctl->status;
	printf("ioctl return status=%d\n", dev_ioctl->status);

	if (status) {
		memset(in_buf, 0, SDOS_ENCRYPTED_MAX_SZ);
		memset(out_buf, 0, SDOS_DECRYPTED_MAX_SZ);
		free(in_buf);
		free(out_buf);
		memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
		free(dev_ioctl);
		return status;
	}

	/* Save result in binary file */
	fp = fopen(outfilename, "wbx");
	if (!fp) {
		fprintf(stderr, "can't open %s for writing: %s\n",
			outfilename, strerror(errno));
		memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
		free(dev_ioctl);
		memset(in_buf, 0, SDOS_ENCRYPTED_MAX_SZ);
		memset(out_buf, 0, SDOS_DECRYPTED_MAX_SZ);
		free(in_buf);
		free(out_buf);
		return -1;
	}

	aes_hdr = (struct fcs_aes_crypt_header *)out_buf;
	if (verbose)
		dump_aes_hdr(aes_hdr);

	if (verbose) {
		printf("Save decrypted data to %s\n", outfilename);
		printf("Saving %d [0x%X] bytes\n",
			(aes_hdr->data_len - aes_hdr->pad),
			(aes_hdr->data_len - aes_hdr->pad));
	}

	/* Write out the data but skip the header */
	fwrite(out_buf + sizeof(struct fcs_aes_crypt_header),
	       (aes_hdr->data_len - aes_hdr->pad), 1, fp);

	fclose(fp);
	memset(in_buf, 0, SDOS_ENCRYPTED_MAX_SZ);
	memset(out_buf, 0, SDOS_DECRYPTED_MAX_SZ);
	free(in_buf);
	free(out_buf);
	memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
	free(dev_ioctl);

	return status;
}

/*
 * trng_random_number() - get a random number
 * @filename: Filename to save result into.
 * @verbose: verbosity of output (true = more output)
 *
 * Return: 0 on success, or error on failure
 */
static int fcs_random_number(char *filename, bool verbose)
{
	struct intel_fcs_dev_ioctl *dev_ioctl;
	int status;
	FILE *fp;
	int i;

	dev_ioctl = (struct intel_fcs_dev_ioctl *)
			malloc(sizeof(struct intel_fcs_dev_ioctl));
	if (!dev_ioctl) {
		fprintf(stderr, "can't malloc %s:  %s\n", dev, strerror(errno));
		return -1;
	}

	/* Fill in the structure */
	for (i = 0; i < 8; i++)
		dev_ioctl->com_paras.rn_gen.rndm[i] = 0;
	dev_ioctl->status = -1;

	fcs_send_ioctl_request(dev_ioctl, INTEL_FCS_DEV_RANDOM_NUMBER_GEN);

	printf("ioctl return status=0x%x\n", dev_ioctl->status);

	if (verbose)
		/* print random result data */
		for (i = 0; i < 8; i++)
			printf("RND output[%d]=%d\n", i,
				dev_ioctl->com_paras.rn_gen.rndm[i]);

	/* Save result in binary file */
	fp = fopen(filename, "wbx");
	if (!fp) {
		fprintf(stderr, "can't open %s for writing: %s\n",
			filename, strerror(errno));
		memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
		free(dev_ioctl);
		return -1;
	}

	fwrite(dev_ioctl->com_paras.rn_gen.rndm,
	       sizeof(dev_ioctl->com_paras.rn_gen.rndm), 1, fp);

	fclose(fp);

	status = dev_ioctl->status;
	memset(dev_ioctl, 0, sizeof(struct intel_fcs_dev_ioctl));
	free(dev_ioctl);

	return status;
}

/*
 * error_exit()
 * @msg: the message error
 *
 * No return code
 */
static void error_exit(char *msg)
{
	printf("ERROR: %s\n", msg);
	exit(1);
}

int main(int argc, char *argv[])
{
	enum intel_fcs_command_code command = INTEL_FCS_DEV_COMMAND_NONE;
	char *filename = NULL, *outfilename = NULL;
	int ret = 0, c, index = 0, prnt = 0;
	int type = -1;
	int32_t test = -1;
	uint64_t own = 0;
	int16_t id = 0;
	char *endptr;
	bool verbose = false;

	while ((c = getopt_long(argc, argv, "phvEDR:t:V:C:G:o:d:i:r:c:",
				opts, &index)) != -1) {
		switch (c) {
		case 'V':
			if (command != INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Only one command allowed");
			command = INTEL_FCS_DEV_VALIDATE_REQUEST_CMD;
			filename = optarg;
			break;
		case 't':
			if (type != -1)
				error_exit("Only one type allowed");
			type = atoi(optarg);
			if ((type != INTEL_FCS_IMAGE_HPS) &&
			    (type > INTEL_FCS_IMAGE_BITSTREAM))
				error_exit("Invalid type");
			break;
		case 'C':
			if (command != INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Only one command allowed");
			command = INTEL_FCS_DEV_COUNTER_SET_CMD;
			filename = optarg;
			break;
		case 'c':
			if (command != INTEL_FCS_DEV_COUNTER_SET_CMD)
				error_exit("Only one command allowed");
			test = atoi(optarg);
			break;
		case 'G':
			if (command != INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Only one command allowed");
			command = INTEL_FCS_DEV_GET_PROVISION_DATA_CMD;
			filename = optarg;
			break;
		case 'p':
			if (command != INTEL_FCS_DEV_GET_PROVISION_DATA_CMD)
				error_exit("Print not valid with this command");
			prnt = 1;
			break;
		case 'R':
			if (command != INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Only one command allowed");
			command = INTEL_FCS_DEV_RANDOM_NUMBER_GEN_CMD;
			filename = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case 'E':
			if (command != INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Only one command allowed");
			command = INTEL_FCS_DEV_DATA_ENCRYPTION_CMD;
			break;
		case 'D':
			if (command != INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Only one command allowed");
			command = INTEL_FCS_DEV_DATA_DECRYPTION_CMD;
			break;
		case 'o':
			if (command == INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Outfile needs command");
			outfilename = optarg;
			break;
		case 'i':
			if (command == INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Input file needs command");
			filename = optarg;
			break;
		case 'd':
			if (command == INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("ASOI needs command");
			id = strtoul(optarg, 0, 0);
			if (errno)
				error_exit("ASOI conversion error");
			break;
		case 'r':
			if (command == INTEL_FCS_DEV_COMMAND_NONE)
				error_exit("Owner Hash needs command");
			own = strtoull(optarg, &endptr, 16);
			if (*endptr)
				error_exit("Owner ID conversion error");
			break;
		case 'h':
		default:
			fcs_client_usage();
			exit(1);
			break;
		}
	}

	switch (command) {
	case INTEL_FCS_DEV_VALIDATE_REQUEST_CMD:
		if (!filename || (type == -1))
			error_exit("Incorrect Type - must be 0 (HPS) or 1 (bitstream)");
		ret = fcs_validate_request(filename, type, verbose);
		break;
	case INTEL_FCS_DEV_RANDOM_NUMBER_GEN_CMD:
		if (!filename)
			error_exit("Missing filename to save data into");
		ret = fcs_random_number(filename, verbose);
		break;
	case INTEL_FCS_DEV_COUNTER_SET_CMD:
		if (!filename)
			error_exit("Missing filename with Counter Set Data");
		if ((test != 0) && (test != 1))
			error_exit("Error with test bit - must be 0 or 1");
		ret = fcs_service_counter_set(filename, test);
		break;
	case INTEL_FCS_DEV_GET_PROVISION_DATA_CMD:
		if (!filename)
			error_exit("Missing filename to save Provision Data");
		ret = fcs_service_get_provision_data(filename, prnt);
		break;
	case INTEL_FCS_DEV_DATA_ENCRYPTION_CMD:
		if (!filename || !outfilename)
			error_exit("Missing input or output filename");
		ret = fcs_sdos_encrypt(filename, outfilename, id, own, verbose);
		break;
	case INTEL_FCS_DEV_DATA_DECRYPTION_CMD:
		if (!filename || !outfilename)
			error_exit("Missing input or output filename");
		ret = fcs_sdos_decrypt(filename, outfilename, verbose);
		break;
	case INTEL_FCS_DEV_COMMAND_NONE:
	default:
		fprintf(stderr, "Invalid Input Command [0x%X]\n", command);
		fcs_client_usage();
		break;
	}

	/* add hard delay to make sure the opertion is completed */
	/* or change app to poll the operation status */
	sleep(1);

	return ret;
}
