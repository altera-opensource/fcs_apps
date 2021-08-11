// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2021, Intel Corporation
 */

#include <byteswap.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>

#include "intel_fcs_structs.h"
#include "sha2.h"

#define FCS_CERT_HEADER_SZ	(sizeof(struct fcs_hps_generic_header))

#define CMF_AUTH_CERT_EFUSE	5
#define CMF_AUTH_CERT_VAB	6

#define BYTES_PER_WORD		(sizeof(uint32_t) / sizeof(uint8_t))
#define CERT_LENGTH_SZ		BYTES_PER_WORD

#define OUTPUT_CERT_NAME	"unsigned_cert.ccert"
#define SIGNED_CERT_NAME	"signed_finished_cert.ccert"
#define VAB_OUTPUT_FILENAME	"hps_image_signed.vab"

/*
 * option_ops - translate the long options to short options
 *
 * The main commands are uppercase. The parameters are lowercase.
 *
 */
static const struct option opts[] = {
	{"hps_cert", required_argument, NULL, 'H'},
	{"counter_set", no_argument, NULL, 'C'},
	{"key", no_argument, NULL, 'K'},
	{"test", required_argument, NULL, 't'},
	{"counter", required_argument, NULL, 'c'},
	{"select", required_argument, NULL, 's'},
	{"key_type", required_argument, NULL, 'k'},
	{"key_id", required_argument, NULL, 'i'},
	{"key_size", required_argument, NULL, 'x'},
	{"key_usage", required_argument, NULL, 'u'},
	{"gen_cs_key", required_argument, NULL, 'G'},
	{"print_cs_key", required_argument, NULL, 'P'},
	{"roothash", required_argument, NULL, 'r'},
	{"finish", required_argument, NULL, 'F'},
	{"textfile", required_argument, NULL, 't'},
	{"imagefile", required_argument, NULL, 'f'},
	{"print", no_argument, NULL, 'p'},
	{"verbose", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0}
};

/*
 * fcs_prepare_usage() - show the usage of client application
 *
 * This function doesn't have a return value.
 *
 */
static void fcs_prepare_usage(void)
{
	printf("\n--------------------------------------------\n");
	printf("--- Crypto Services Configure Tool Usage ---");
	printf("\n--------------------------------------------\n");

	printf("%-32s  %s", "-H|--hps_cert <HPS_image_filename>\n",
	       "Create the unsigned certificate for an HPS VAB image.\n");
	printf("  Output result is saved in filename = %s\n\n", OUTPUT_CERT_NAME);

	printf("%-32s  %s  %s  %s  %s", "-C|--counter_set -s <counter_select> -c <counter_value>\n",
	       "Create the unsigned certificate for a Counter Set command.\n",
	       "if counter_set=1, set Big Counter to counter_value (range 0 to 495)\n",
	       "if counter_set=2-5, set Security Version Counter to counter_value (range 0 to 64)\n",
	       "if counter_value=-1 and counter_set=1-5, then can update the selected counter w/o signed certificate\n");
	printf("  Output result is saved in filename = %s\n\n", OUTPUT_CERT_NAME);

	printf("%-32s  %s  %s", "-K|--key -k|--key_type <user(0)/intel(1)> -i|--key_id <key_id> [-r|--roothash <filename>]\n",
	       "Create the unsigned certificate for a Key Cancellation command.\n",
	       "For User Key, roothash selects User Root Hash, Key ID can be 0 to 31.\n");
	printf("  Output result is saved in filename = %s\n\n", OUTPUT_CERT_NAME);

	printf("%-32s  %s  %s", "-F|--finish <signed_certificate> [-f|--imagefile <HPS_image_filename>]\n",
	       "Concatentate the size to the certificate. If supplied, concatenate signed certficate to HPS VAB image.\n",
	       "Output result is saved in filename = hps_image_signed.vab\n\n");

	/* Crypto service key object helper */
	printf("%-32s  %s  %s  %s  %s  %s  %s", "-G|--gen_cs_key <output_crypto_service_key_object_file>\n",
	       "-i|--key_id <non-zero unique id>\n",
	       "-x|--key_size <128|256|384|512>\n",
	       "-k|--key_type <AES(1)/HMAC(2)/ECC NIST P Curve(3)/ECC-BrainPool(4)>\n",
	       "-u|--key_usage <key usage bitmask. Encrypt(b0)|Decrypt(b1)|Sign(b2)|Verify(b3)|Exchange(b4)>\n",
	       "-t|--textfile <text file contains key data in hexadecimal>\n",
	       "Generate unprotected crypto service key object file.\n\n");
	printf("%-32s  %s", "-P|--print_cs_key <crypto_service_key_object_file>\n",
	       "Decode and print input crypto service key object file.\n\n");

	printf("%-32s  %s", "-v|--verbose", "Show additional messages\n\n");
	printf("%-32s  %s", "-h|--help", "Show usage message\n");
	printf("--------------------------------------------\n");
	printf("\n");
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
static int calc_fit_image_hash(uint8_t *hps_buf, size_t hps_bufsize,
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
 * fcs_finish_cert() - append the size of the signed certificate and
 *		concatenate to HPS image.
 *
 * Return: 0 on success, or error on failure
 *
 */
static int fcs_finish_cert(char *cert_filename, char *image_filename, bool verbose)
{
	uint32_t cert_sz, image_sz, sign_cert_sz;
	uint8_t *fcs_vab_cert, *hps_buff;
	FILE *fpi, *fpo;
	struct stat st;
	size_t sz;

	if (!cert_filename) {
		fprintf(stderr, "NULL file passed in:\n");
		return -1;
	}
	/* Read the certificate data */
	fpi = fopen(cert_filename, "rbx");
	if (!fpi) {
		fprintf(stderr, "Unable to open file %s:  %s\n",
			cert_filename, strerror(errno));
		return -1;
	}
	if (fstat(fileno(fpi), &st)) {
		fprintf(stderr, "Unable to get filesize of %s:  %s\n",
			cert_filename, strerror(errno));
		fclose(fpi);
		return -1;
	}
	cert_sz = st.st_size;

	if (verbose)
		printf("%s[%d] filesize=%d[0x%X]\n", __func__, __LINE__,
			cert_sz, cert_sz);

	/* Signed HPS Certificate includes a length word at the end */
	sign_cert_sz = cert_sz + CERT_LENGTH_SZ;
	/* Allocate a buffer for the certificate + size of certificate */
	fcs_vab_cert = calloc(sign_cert_sz, sizeof(uint8_t));
	if (!fcs_vab_cert) {
		fprintf(stderr, "can't calloc buffer for certificate:  %s\n",
			strerror(errno));
		fclose(fpi);
		return -1;
	}

	/* Reset file handle to beginning of file */
	fseek(fpi, 0, SEEK_CUR);
	sz = fread(fcs_vab_cert, 1, cert_sz, fpi);
	fclose(fpi);
	if (sz != cert_sz) {
		fprintf(stderr, "Problem reading data into buffer %s:  %s\n",
			cert_filename, strerror(errno));
		free(fcs_vab_cert);
		return -1;
	}
	/* Concatenate the filesize to the certificate */
	memcpy(&fcs_vab_cert[cert_sz], &cert_sz, CERT_LENGTH_SZ);

	/* Concatenate signature after HPS Image */
	if (image_filename) {
		struct fcs_hps_vab_certificate_header *fcs_vab_hdr;
		struct fcs_hps_vab_certificate_data *fcs_data;
		uint8_t sha384[SHA512_DIGEST_SIZE];
		uint32_t pad = 0, padded_sz;
		int ret, i;

		fpi = fopen(image_filename, "rbx");
		if (!fpi) {
			fprintf(stderr, "Unable to open file %s:  %s\n",
				image_filename, strerror(errno));
			free(fcs_vab_cert);
			return -1;
		}

		if (fstat(fileno(fpi), &st)) {
			fprintf(stderr, "Unable to get filesize of %s:  %s\n",
				cert_filename, strerror(errno));
			free(fcs_vab_cert);
			fclose(fpi);
			return -1;
		}
		image_sz = st.st_size;
		/* filesize must be on a word boundary */
		if (image_sz % BYTES_PER_WORD) {
			pad = BYTES_PER_WORD - (image_sz % BYTES_PER_WORD);
			printf("%s[%d] filesize not on word boundary. Padding with %d bytes\n",
				__func__, __LINE__, pad);
		}
		padded_sz = image_sz + pad;

		/* Allocate a buffer and read the file into the buffer */
		hps_buff = calloc(padded_sz, sizeof(uint8_t));
		if (!hps_buff) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				image_filename, strerror(errno));
			free(fcs_vab_cert);
			fclose(fpi);
			return -1;
		}

		/* Reset file handle to beginning of file */
		fseek(fpi, 0, SEEK_CUR);
		sz = fread(hps_buff, 1, image_sz, fpi);
		fclose(fpi);

		if (sz != image_sz) {
			fprintf(stderr, "Problem reading data into buffer %s\n",
				image_filename);
			free(hps_buff);
			free(fcs_vab_cert);
			return -1;
		}
		/* Validate certificate hash against HPS image */
		ret = calc_fit_image_hash(hps_buff, padded_sz, sha384);
		if (ret) {
			fprintf(stderr, "Problem calculating SHA384 hash\n");
			free(hps_buff);
			free(fcs_vab_cert);
			return -1;
		}
		fcs_vab_hdr = (struct fcs_hps_vab_certificate_header *)fcs_vab_cert;
		fcs_data = (struct fcs_hps_vab_certificate_data *)&fcs_vab_hdr->d;
		for (i = 0; i < SHA384_SZ; i++) {
			if (verbose)
				printf("Calc = %02x; Hdr = %02x\n",
					sha384[i], fcs_data->fcs_sha384[i]);
			if (sha384[i] != fcs_data->fcs_sha384[i]) {
				fprintf(stderr, "Calculated SHA384 hash doesn't match certificate\n");
				free(hps_buff);
				free(fcs_vab_cert);
				return -1;
			}
		}

		/* save file with HPS image data followed by signed certificate */
		fpo = fopen(VAB_OUTPUT_FILENAME, "wbx");
		if (!fpo) {
			fprintf(stderr, "Unable to open file %s:  %s\n",
				VAB_OUTPUT_FILENAME, strerror(errno));
			free(hps_buff);
			free(fcs_vab_cert);
			return -1;
		}
		fwrite(hps_buff, 1, padded_sz, fpo);
		fwrite(fcs_vab_cert, 1, sign_cert_sz, fpo);
		fclose(fpo);
		free(hps_buff);
	} else {
		/* No image - Write the finished signed certificate out. */
		fpo = fopen(SIGNED_CERT_NAME, "wbx");
		if (!fpo) {
			fprintf(stderr, "Unable to open file %s:  %s\n",
				SIGNED_CERT_NAME, strerror(errno));
			free(fcs_vab_cert);
			return -1;
		}
		fwrite(fcs_vab_cert, 1, sign_cert_sz, fpo);
		fclose(fpo);
	}

	free(fcs_vab_cert);

	return 0;
}

/*
 * fcs_generate_cert() - create an HPS certificate
 * @cert_type: type of image
 * @data: Certificate data to be copied.
 * @data_sz: size of data to be copied.
 *
 * Return: 0 on authorization success, or error on failure
 *
 */
static int fcs_generate_cert(uint32_t cert_type, void *data, size_t data_sz)
{
	struct fcs_hps_generic_header *fcs_vab_cert;
	FILE *fpo;

	/* Allocate a buffer for the certificate */
	fcs_vab_cert = calloc(FCS_CERT_HEADER_SZ, sizeof(uint8_t));
	if (!fcs_vab_cert) {
		fprintf(stderr, "can't calloc buffer for certificate:  %s\n",
			strerror(errno));
		return -1;
	}
	/* generate the header */
	fcs_vab_cert->cert_magic_num = SDM_CERT_MAGIC_NUM;
	fcs_vab_cert->cert_data_sz = FCS_CERT_HEADER_SZ;
	fcs_vab_cert->cert_ver = 0;
	fcs_vab_cert->cert_type = cert_type;
	/* Copy the data in */
	memcpy(fcs_vab_cert->fcs_data, data, data_sz);
	/* Write the data out. */
	fpo = fopen(OUTPUT_CERT_NAME, "wbx");
	if (!fpo) {
		fprintf(stderr, "Unable to open file %s:  %s\n",
			OUTPUT_CERT_NAME, strerror(errno));
		free(fcs_vab_cert);
		return -1;
	}
	fwrite(fcs_vab_cert, 1, FCS_CERT_HEADER_SZ, fpo);
	fclose(fpo);
	free(fcs_vab_cert);

	return 0;
}

/*
 * fcs_prepare_image() - create an unsigned HPS image certificate
 * @filename: FIT filename to sign
 * @fcs_type: type of image
 * @verbose: If true, print verbose output
 *
 * Return: 0 on authorization success, or error on failure
 *
 */
static int fcs_prepare_image(char *filename, int fcs_type, bool verbose)
{
	size_t sz, filesize;
	uint8_t *hps_buff;
	struct stat st;
	FILE *fp;

	/* Handle the HPS file. Ignore bitstream files */
	if (!fcs_type) {
		struct fcs_hps_vab_certificate_data fcs_data;
		int i, ret, padded_sz, pad = 0;

		if (!filename) {
			fprintf(stderr, "NULL filename:  %s\n", strerror(errno));
			return -1;
		}

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
			printf("%s[%d] filesize=%ld[0x%lX]\n", __func__, __LINE__,
				filesize, filesize);

		/* filesize must be on a word boundary */
		if (filesize % BYTES_PER_WORD) {
			pad = BYTES_PER_WORD - (filesize % BYTES_PER_WORD);

			printf("%s[%d] filesize not on word boundary. Padding with %d bytes\n",
				__func__, __LINE__, pad);
		}
		padded_sz = filesize + pad;

		memset(&fcs_data, 0, sizeof(fcs_data));
		/* Allocate a buffer and read the file into the buffer */
		hps_buff = calloc(padded_sz, sizeof(uint8_t));
		if (!hps_buff) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			fclose(fp);
			return -1;
		}
		/* Reset file handle to beginning of file */
		fseek(fp, 0, SEEK_CUR);
		sz = fread(hps_buff, 1, filesize, fp);
		fclose(fp);

		if (verbose)
			printf("%s[%d] sz=%ld, filesize=%ld\n", __func__, __LINE__,
				sz, filesize);
		if (sz != filesize) {
			fprintf(stderr, "Problem reading data into buffer %s:  %s\n",
				filename, strerror(errno));
			free(hps_buff);
			return -1;
		}

		/* compute the Image hash */
		ret = calc_fit_image_hash(hps_buff, padded_sz, fcs_data.fcs_sha384);
		if (ret) {
			fprintf(stderr, "Error calculating SHA384 hash\n");
			free(hps_buff);
			return -1;
		}

		if (verbose)
		/* Print the hash result */
			for (i = 0; i < SHA384_SZ; i += 8) {
				printf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
				       fcs_data.fcs_sha384[i],
				       fcs_data.fcs_sha384[i + 1],
				       fcs_data.fcs_sha384[i + 2],
				       fcs_data.fcs_sha384[i + 3],
				       fcs_data.fcs_sha384[i + 4],
				       fcs_data.fcs_sha384[i + 5],
				       fcs_data.fcs_sha384[i + 6],
				       fcs_data.fcs_sha384[i + 7]);
			}
		free(hps_buff);

		/* Populate the rest of the structure */
		fcs_data.rsvd0_0 = 0;
		fcs_data.flags = 0;

		ret = fcs_generate_cert(CMF_AUTH_CERT_VAB, &fcs_data, VAB_DATA_SZ);
		if (ret) {
			fprintf(stderr, "can't generate certificate:  %s\n",
				strerror(errno));
			return ret;
		}
	}

	return 0;
}

/*
 * fcs_prepare_counter() - create an unsigned counter certificate
 * @counter_select: Which counter to set (1 to 5)
 * @counter_val: Value to set counter to
 * @verbose: If true, print verbose output
 *
 * Return: 0 on success, or error on failure
 *
 */
static int fcs_prepare_counter(uint8_t counter_select, uint32_t counter_val,
			       bool verbose)
{
	struct fcs_counter_set_data fcs_data;
	int ret;

	memset(&fcs_data, 0, sizeof(fcs_data));
	/* Fill in the fcs_data structure */
	fcs_data.select.counter_type = counter_select;
	fcs_data.select.subcounter_type = 0;
	/* Key Cancellation Request? */
	fcs_data.fcs_counter_value = counter_val;

	ret = fcs_generate_cert(CMF_AUTH_CERT_EFUSE, &fcs_data, VAB_DATA_SZ);
	if (ret) {
		fprintf(stderr, "can't generate certificate:  %s\n",
			strerror(errno));
		return ret;
	}

	return 0;
}

/*
 * fcs_prepare_key() - create an unsigned key cancellation certificate
 * @key_type: 0 for intel fuses, 1 for user keys using explicit key ID
 * @key_id: Key ID to be cancelled, -1 means to cancel the owner root
 *          hash if cancellation type is for user keys.
 * @verbose: If true, print verbose output
 *
 * Return: 0 on success, or error on failure
 *
 */
static int fcs_prepare_key(int key_type, int key_id,
			   char *filename, bool verbose)
{
	struct fcs_counter_set_data fcs_data;
	int i, ret;
	FILE *fp;

	memset(&fcs_data, 0, sizeof(fcs_data));
	/* Fill in the fcs_cs structure */
	if ((key_id == -1) && (key_type == FCS_USER_KEY))
		fcs_data.select.counter_type = 255;
	else
		fcs_data.select.counter_type = 0;
	fcs_data.select.subcounter_type = key_type;
	fcs_data.fcs_counter_value = key_id;
	/* User type requires a Root Hash */
	if (key_type == FCS_USER_KEY) {
		struct stat st;
		int hash_sz, filesz;

		if (verbose)
			printf("%s[%d] filename=%s\n", __func__, __LINE__, filename);

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
		filesz = st.st_size;

		fseek(fp, 0, SEEK_CUR);
		hash_sz = fread(fcs_data.root_hash, 1, sizeof(fcs_data.root_hash), fp);
		fclose(fp);
		if ((hash_sz != filesz) || (hash_sz != SHA384_SZ)) {
			fprintf(stderr, "Roothash file is incorrect size %d\n", filesz);
			return -1;
		}

		if (verbose) {
			printf("%s[%d] roothash size=%d[0x%X]\n",
				__func__, __LINE__, hash_sz, hash_sz);

			for (i = 0; i < sizeof(fcs_data.root_hash) / sizeof(uint8_t);
			     i += 4)
				printf("roothash[%d]=[0x%x, 0x%x, 0x%x, 0x%x]\n", i,
					fcs_data.root_hash[i], fcs_data.root_hash[i + 1],
					fcs_data.root_hash[i + 2], fcs_data.root_hash[i + 3]);
		}
	}

	ret = fcs_generate_cert(CMF_AUTH_CERT_EFUSE, &fcs_data, VAB_DATA_SZ);
	if (ret)
		fprintf(stderr, "can't generate certificate:  %s\n",
			strerror(errno));

	return ret;
}

/*
 * fcs_prepare_generate_cs_key_object() - create unprotected crypto
 * service key object file.
 * @key_id: Non-zero unique key id.
 * @key_size: 128 | 256 | 384 | 512 bits
 * @key_type: AES(1)/HMAC(2)/ECC NIST P Curve(3)/ECC-BrainPool(4)
 * @key_usage: bitmask (b0:Encrypt | b1:Decrypt | b2:Sign | b3:Verify | b4:Exchange)
 * @key_data_file: Text file that contains key data in hexadecimal
 * @key_obj_file: Output binary crypto service key object file
 * @verbose: If true, print verbose output
 *
 * Return: 0 on success, or error on failure
 *
 */
static int fcs_prepare_generate_cs_key_object(unsigned int key_id, int key_size,
			   unsigned int key_type, unsigned int key_usage,
			   char *key_data_file, char *key_obj_file, bool verbose)
{
	int ret = -1;
	int buffer_size = FCS_CS_KEY_OBJECT_MAX_SZ;
	uint8_t *buffer;
	unsigned int key_usage_mask = key_usage;
	struct fcs_cs_key_object_data object;
	struct stat st;
	int key_half_byte_size;
	int filesz;
	FILE *fpi, *fpo;

	printf("\n---- Generate crypto service key object file ---- \n");

	if (key_id == -1 || key_id == 0 || key_usage == 0 || key_data_file == NULL || key_obj_file == NULL) {
		printf("Invalid inputs. key_id=%d key_usage=%02x key_data_file=%p key_obj_file=%p\n",
			key_id, key_usage, key_data_file, key_obj_file);
		return ret;
	}

	/* @key_size: 128 | 256 | 384 | 512 bits */
	if (key_size != 128 && key_size != 256 && key_size != 384 && key_size != 512) {
		printf("Invalid key size\n");
		return ret;
	}

	/* @key_type: AES(1)/HMAC(2)/ECC NIST P Curve(3)/ECC-BrainPool(4) */
	if (key_type < 1 || key_type > 4) {
		printf("Invalid key type\n");
		return ret;
	}

	/* @key_usage: bitmask (b0:Encrypt | b1:Decrypt | b2:Sign | b3:Verify | b4:Exchange) */
	switch (key_type) {
	case 1:
		key_usage_mask &= ~(0x3);
		if (key_size != 128 && key_size != 256) {
			printf("Mismatch between key type and key size\n");
			return ret;
		}
		break;
	case 2:
		key_usage_mask &= ~(0xC);
		if (key_size != 256 && key_size != 384 && key_size != 512) {
			printf("Mismatch between key type and key size\n");
			return ret;
		}
		break;
	case 3:
	case 4:
		/* Sign+Verify and Exchange are exclusive to each other */
		if (key_usage_mask & 0xC)
			key_usage_mask &= ~(0xC);
		else
			key_usage_mask &= ~(0x10);

		if (key_size != 256 && key_size != 384) {
			printf("Mismatch between key type and key size\n");
			return ret;
		}
		break;
	}
	if (key_usage_mask) {
		printf("Mismatch between key type and key usage\n");
		return ret;
	}

	/* Prepare object */
	memset(&object, 0, sizeof(struct fcs_cs_key_object_data));
	object.key_id = key_id;
	object.key_type = key_type;
	object.key_usage = key_usage;
	object.key_size = key_size;

	/* Read key data from key_data_file */
	fpi = fopen(key_data_file, "r");
	if (!fpi) {
		fprintf(stderr, "Unable to open file %s:  %s\n",
			key_data_file, strerror(errno));
		return ret;
	}
	if (fstat(fileno(fpi), &st)) {
		fclose(fpi);
		fprintf(stderr, "Unable to get filesize %s:  %s\n",
			key_data_file, strerror(errno));
		return ret;
	}
	filesz = st.st_size;
	key_half_byte_size = key_size / 4;

	/* Exclude last EOL byte when checking file size */
	if (filesz - 1 < key_half_byte_size) {
		fclose(fpi);
		printf("Key data file contains %d chars, "
		       "but the key_size (%d bits) expects %d chars\n",
			filesz - 1, key_size, key_half_byte_size);
		return ret;
	} else {
		char c;
		int idx = 0;
		uint8_t hex;
		uint8_t low = 0;

		if (filesz - 1 > key_half_byte_size) {
			printf("Key data is truncated. Key data file contains %d chars, "
			       "but key_size (%d bits) only requires %d chars\n",
				filesz - 1, key_size, key_half_byte_size);
		}

		do {
			c = (char)fgetc(fpi);
			hex = fcs_cs_convert_char_to_hex(c);
			if (low) {
				object.data[idx] |= hex;
				idx++;
			} else {
				object.data[idx] |= (hex << 4);
			}
			low ^= 1;
			key_half_byte_size--;
		} while (key_half_byte_size > 0);
		fclose(fpi);
	}

	/* Generate crypto service key object binary file */
	buffer = calloc(buffer_size, sizeof(uint8_t));
	if (buffer) {
		if (verbose)
			fcs_cs_key_object_print(&object);

		ret = fcs_cs_key_object_encode(&object, buffer, &buffer_size);
		if (ret == 0) {
			struct stat fbuffer;
			if (stat(key_obj_file, &fbuffer) == 0)
				remove(key_obj_file);

			fpo = fopen(key_obj_file, "wbx");
			if (!fpo) {
				fprintf(stderr, "Unable to open file %s:  %s\n",
					key_obj_file, strerror(errno));
				free(buffer);
				return -1;
			}
			fwrite(buffer, 1, buffer_size, fpo);
			fclose(fpo);

			printf("Successfully generate %s file with %d bytes\n",
				key_obj_file, buffer_size);
		}
		free(buffer);
	} else {
		printf("Failed to allocate memory\n");
	}

	return ret;
}

/*
 * fcs_prepare_print_cs_key_object() - decode and print crypto service
 * key object file.
 * @key_obj_file: Crypto service key object file
 * @verbose: If true, print verbose output
 *
 * Return: 0 on success, or error on failure
 *
 */
static int fcs_prepare_print_cs_key_object(char *key_obj_file, bool verbose)
{
	int ret = -1;
	int buffer_size = FCS_CS_KEY_OBJECT_MAX_SZ;
	uint8_t *buffer = NULL;
	struct fcs_cs_key_object_data object;
	FILE *fp;

	printf("\n---- Decode and print crypto service key object file ---- \n");

	if (key_obj_file == NULL) {
		printf("Invalid inputs. key_obj_file=%p\n", key_obj_file);
		return ret;
	}

	buffer = calloc(buffer_size, sizeof(uint8_t));
	if (buffer) {
		struct stat st;
		int filesz;

		/* Open binary file */
		fp = fopen(key_obj_file, "rbx");
		if (!fp) {
			fprintf(stderr, "Unable to open file %s:  %s\n",
				key_obj_file, strerror(errno));
			free(buffer);
			return -1;
		}
		/* Get the file statistics */
		if (fstat(fileno(fp), &st)) {
			fclose(fp);
			fprintf(stderr, "Unable to open file %s:  %s\n",
				key_obj_file, strerror(errno));
			free(buffer);
			return -1;
		}

		filesz = st.st_size;
		if (filesz <= buffer_size) {
			/* Copy binary to buffer */
			fseek(fp, 0, SEEK_CUR);
			buffer_size = fread(buffer, 1, filesz, fp);
			/* Decode and dump key content */
			ret = fcs_cs_key_object_decode(&object, buffer, buffer_size);
			if (ret == 0) {
				printf("Successfully decode %s file with %d bytes\n",
					key_obj_file, buffer_size);

				fcs_cs_key_object_print(&object);
			}
		} else {
			/* print error file size mismatch */
			printf("File size mismatch (file size %d beyond limited size %d bytes)\n",
				filesz, buffer_size);
		}

		fclose(fp);
		free(buffer);
	} else {
		printf("Failed to allocate memory\n");
	}

	return ret;
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
	bool verbose = false;
	char *filename = NULL, *hpsfile =  NULL, *textfile = NULL;
	unsigned int key_id = -1, key_usage = 0;
	int key_type = -1, key_size = 0;
	int counter_val = -1, counter_sel = -1;
	int index = 0, type = 0;
	int c;

	while ((c = getopt_long(argc, argv, "hvH:CKc:i:k:r:s:F:f:G:P:x:u:t:",
				opts, &index)) != -1) {
		switch (c) {
		case 'H':
			filename = optarg;
			type = FCS_CMD_TYPE_IMAGE_HPS_VAB;
			printf("%s[%d] filename=%s\n", __func__, __LINE__, filename);
			break;
		case 'C':
			type = FCS_CMD_TYPE_IMAGE_COUNTER_SET;
			break;
		case 'c':
			if (type != FCS_CMD_TYPE_IMAGE_COUNTER_SET)
				error_exit("Wrong command. Only Counter Set Allowed");
			if (counter_val != -1)
				error_exit("Only one counter value allowed");

			counter_val = strtol(optarg, NULL, 0);
			break;
		case 's':
			if (type != FCS_CMD_TYPE_IMAGE_COUNTER_SET)
				error_exit("Wrong command. Only Counter Set Allowed");
			counter_sel = atoi(optarg);
			break;
		case 'K':
			type = FCS_CMD_TYPE_IMAGE_KEY_CANCEL;
			break;
		case 'G':
			filename = optarg;
			type = FCS_CMD_TYPE_GEN_CS_KEY_OBJ;
			break;
		case 'P':
			filename = optarg;
			type = FCS_CMD_TYPE_PRINT_CS_KEY_OBH;
			break;
		case 'k':
			if (key_type != -1)
				error_exit("Only one key type allowed");
			key_type = atoi(optarg);
			if (type != FCS_CMD_TYPE_GEN_CS_KEY_OBJ) {
				if ((key_type != FCS_USER_KEY) &&
				    (key_type != FCS_INTEL_KEY)) {
					key_type = -1;
					error_exit("Invalid key_type (can only be 0 or 1)");
				}
			}
			break;
		case 'i':
			if (key_id != -1)
				error_exit("Only one key id allowed");
			key_id = atoi(optarg);
			if (type != FCS_CMD_TYPE_GEN_CS_KEY_OBJ) {
				if ((key_type == -1) && (key_type != FCS_USER_KEY)) {
					key_type = -1;
					error_exit("Invalid key_id (can only be -1 for user key)");
				}
			}
			break;
		case 'r':
			if (key_type != FCS_USER_KEY)
				error_exit("Roothash only valid for User Keys");
			filename = optarg;
			break;
		case 'x':
			key_size = atoi(optarg);
			break;
		case 'u':
			key_usage = strtol(optarg, NULL, 0);
			break;
		case 't':
			textfile = optarg;
			break;
		case 'F':
			filename = optarg;
			type = FCS_CMD_TYPE_VAB_FINISH;
			break;
		case 'f':
			hpsfile = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			printf("\nError: Unrecognized parameter [%c]\n\n", c);
		case 'h':
			fcs_prepare_usage();
			exit(1);
			break;
		}
	}

	if ((type == FCS_CMD_TYPE_IMAGE_HPS_VAB) && filename) {
		if (verbose)
			printf("%s[%d] filename=%s\n", __func__, __LINE__, filename);
		fcs_prepare_image(filename, type, verbose);
	} else if ((type == FCS_CMD_TYPE_VAB_FINISH) && filename) {
		if (verbose)
			printf("%s[%d] Certificate filename=%s\n", __func__, __LINE__, filename);
		if (verbose && hpsfile)
			printf("%s[%d] HPS filename=%s\n", __func__, __LINE__, hpsfile);
		fcs_finish_cert(filename, hpsfile, verbose);
	} else if (type == FCS_CMD_TYPE_IMAGE_COUNTER_SET) {
		if (counter_sel == -1)
			error_exit("Counter Select parameter not set");
		if ((!counter_sel) || (counter_sel > 5))
			error_exit("Invalid Counter Select parameter (Must be 1 to 5)");
		if ((counter_sel > 1) && (counter_val > 64))
			error_exit("Invalid Counter Value parameter (Counter value must be from 0 to 64)");
		if ((counter_sel == 1) && (counter_val > 495))
			error_exit("Invalid Big Counter parameter (Counter value must be from 0 to 495)");
		if (counter_val == -1)
			printf("the certificated is fully authenticated, ");
			printf("will inform SDM processes and enables unauthenticated updates to the PTS counter\n");

		if (verbose)
			printf("%s[%d] Counter Set: counter_sel=%d, counter_val=0x%x\n",
				__func__, __LINE__, counter_sel, counter_val);
		fcs_prepare_counter(counter_sel, counter_val, verbose);
	} else if (type == FCS_CMD_TYPE_IMAGE_KEY_CANCEL) {
		if (key_type == -1)
			error_exit("Key Type parameter not set");
		if (key_id == -1)
			error_exit("Key ID parameter not set");

		if (verbose)
			printf("%s[%d] Key Cancel: type=%d, key_type=%d, key_id=%d\n",
				__func__, __LINE__, type, key_type, key_id);
		if (filename && (key_type != FCS_USER_KEY))
			error_exit("Roothash filename only valid for User Keys");
		if ((key_type == FCS_USER_KEY) && !filename)
			error_exit("Roothash filename required for User Keys");
		if ((key_type == FCS_USER_KEY) && (key_id > 31))
			error_exit("Invalid Key ID parameter (Must be in range 0 to 31)");

		fcs_prepare_key(key_type, key_id, filename, verbose);

	} else if (type == FCS_CMD_TYPE_GEN_CS_KEY_OBJ) {
		if (fcs_prepare_generate_cs_key_object(key_id, key_size,
			key_type, key_usage, textfile, filename, verbose)) {
			error_exit("Fail to generate crypto service key object file.");
		}

	} else if (type == FCS_CMD_TYPE_PRINT_CS_KEY_OBH) {
		if (fcs_prepare_print_cs_key_object(filename, verbose)) {
			error_exit("Fail to print crypto service key object file.");
		}

	} else {
		printf("%s[%d] Unrecognized request\n", __func__, __LINE__);
		fcs_prepare_usage();
		exit(1);
	}

	return 0;
}
