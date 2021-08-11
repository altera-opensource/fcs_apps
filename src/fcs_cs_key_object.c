// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021, Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "intel_fcs_structs.h"

/*
 * fcs_cs_convert_char_to_hex() - convert hex charactor to binary
 * @c: hex charactor
 *
 * Return: hex value
 *
 */
uint8_t fcs_cs_convert_char_to_hex(char c)
{
	uint8_t hex = 0;

	if (c >= '0' && c <= '9') {
		hex = c  - '0';
	} else if (c >= 'A' && c <= 'F') {
		hex = c  - 'A' + 10;
	} else if (c >= 'a' && c <= 'f') {
		hex = c  - 'a' + 10;
	}

	return hex;
}

/*
 * fcs_cs_key_object_encode() - convert key object to binary format
 * @object: crypto service key object
 * @buffer: buffer to store key object binary
 * @size: caller need to fill in maximun buffer size and this
 *        function will overwrite with actual key object size
 *
 * Return: 0 on success, or error on failure
 *
 */
int fcs_cs_key_object_encode(struct fcs_cs_key_object_data *object, uint8_t *buffer, int *size)
{
	uint8_t i;
	uint32_t *buffer_u32;
	int byte_size;

	if (object == NULL || buffer == NULL || size == NULL) {
		printf("Invalid parameters (object=%p, buffer=%p, size=%p)\n",
			object, buffer, size);
		return -1;
	}

	i = 0;
	buffer_u32 = (uint32_t *)buffer;

	/* key object magic word */
	buffer_u32[i] = FCS_CS_KEY_OBJECT_MAGIC_WORD;
	i++;
	/* key object size (index = 1), this will be filled in at the end */
	buffer_u32[i] = 0;
	i++;
	/* key unique id */
	buffer_u32[i] = object->key_id;
	i++;
	/* key owner id */
	buffer_u32[i] = 0;
	i++;
	/* key user id */
	buffer_u32[i] = 0;
	i++;
	/* key protection (0x00), wrapped key vertion, key size, key type */
	buffer_u32[i] = 0;
	buffer_u32[i] |= (uint32_t)(object->key_protection);
	buffer_u32[i] |= (uint32_t)(object->key_wrap_version) << 8;
	buffer_u32[i] |= (uint32_t)((object->key_size / 128)) << 16;
	buffer_u32[i] |= (uint32_t)(object->key_type) << 24;
	i++;
	/* Key Usage */
	buffer_u32[i] = object->key_usage;
	i++;
	/*
	 * Usage Condition Data Length
	 * always 0 and it is not supported in this version
	 */
	buffer_u32[i] = 0;
	i++;
	/* Usage Condition Data is not supported in this version */
	/* IV used in Key Protection */
	memcpy(&(buffer[i*4]), object->iv, FCS_CS_KEY_IV_MAX_SZ);
	i += (FCS_CS_KEY_IV_MAX_SZ / 4);
	/* Key Data Magic Word */
	buffer_u32[i] = FCS_CS_KEY_OBJECT_DATA_MAGIC_WORD;
	i++;
	/*
	 * Key Data, must be 32 bytes aligned
	 * padded with 0s to 32 bytes boundary
	 */
	byte_size = (object->key_size / 8);
	if (byte_size % 32 != 0) {
		byte_size += (32 - (byte_size % 32));
	}
	memset(&(buffer[i*4]), 0, byte_size);
	memcpy(&(buffer[i*4]), object->data, (object->key_size / 8));
	i += (byte_size / 4);
	/* MAC - not required in unprotected key */
	/* Last, fill in final key object size */

	*size = i * 4;
	buffer_u32[1] |= *size & 0xFFFF;

	return 0;
}

/*
 * fcs_cs_key_object_decode() - convert binary to key object
 * @object: crypto service key object to store the decode data
 * @buffer: buffer that contains key object binary
 * @size: caller need to provide the key object size
 *
 * Return: 0 on success, or error on failure
 *
 */
int fcs_cs_key_object_decode(struct fcs_cs_key_object_data *object, uint8_t *buffer, int size)
{
	uint8_t i;
	uint32_t *buffer_u32;
	int key_object_size;
	int byte_size;

	if (object == NULL || buffer == NULL || size == 0) {
		printf("Invalid parameters (object=%p, buffer=%p, size=%d)\n",
			object, buffer, size);
		return -1;
	}

	i = 0;
	buffer_u32 = (uint32_t *)buffer;

	/* key object magic word */
	if (buffer_u32[i] != FCS_CS_KEY_OBJECT_MAGIC_WORD) {
		printf("Invalid key object magic word\n");
		return -1;
	}
	i++;
	/* key object size (index = 1) */
	key_object_size = buffer_u32[i] & 0xFFFF;
	if (key_object_size % 4) {
		printf("Key object size %d is not 32 bits misaligned\n", key_object_size);
		return -1;
	}
	i++;
	/* key unique id */
	if (buffer_u32[i] == 0) {
		printf("Invalid key id (must provide non-zero key id)\n");
		return -1;
	}
	object->key_id = buffer_u32[i];
	i++;
	/* key owner id */
	i++;
	/* key user id */
	i++;
	/* key protection (0x00), wrapped key vertion, key size, key type */
	object->key_protection = buffer_u32[i] & 0xFF;
	object->key_wrap_version = (buffer_u32[i] >> 8) & 0xFF;
	object->key_size = ((buffer_u32[i] >> 16) & 0xFF) * 128;
	object->key_type = (buffer_u32[i] >> 24) & 0xFF;
	i++;
	/* Key Usage */
	object->key_usage = buffer_u32[i];
	i++;
	/* Usage Condition Data Length */
	if (buffer_u32[i] != 0) {
		printf("Usage condition data is not supported in this version.\n");
		return -1;
	}
	i++;
	/* Usage Condition Data - future */
	/* IV used in Key Protection */
	memcpy(object->iv, &(buffer[i*4]), FCS_CS_KEY_IV_MAX_SZ);
	i += (FCS_CS_KEY_IV_MAX_SZ / 4);
	/* Key Data Magic Word */
	if (buffer_u32[i] != FCS_CS_KEY_OBJECT_DATA_MAGIC_WORD) {
		printf("Invalid key object data magic word\n");
		return -1;
	}
	i++;
	/* Key Data, must be 32 bytes aligned, padded with 0s to 32 bytes boundary */
	byte_size = (object->key_size / 8);
	if (byte_size % 32 != 0) {
		byte_size += (32 - (byte_size % 32));
	}
	memcpy(object->data, &(buffer[i*4]), (object->key_size / 8));
	i += (byte_size / 4);
	/* MAC */
	if ((i * 4) < key_object_size) {
		memcpy(object->mac, &(buffer[i*4]), FCS_CS_KEY_MAC_MAX_SZ);
		i += (FCS_CS_KEY_MAC_MAX_SZ / 4);
	} else {
		memset(object->mac, 0, FCS_CS_KEY_MAC_MAX_SZ);
	}

	/* Last, cross check object size */
	byte_size = i * 4;
	if (key_object_size != byte_size) {
		printf("Key object size mismatch (actual=%d, expected=%d)\n",
			byte_size, key_object_size);
		return -1;
	}

	return 0;
}

/*
 * fcs_cs_key_object_print() - print key object contents
 * @object: crypto service key object to store the decode data
 *
 * Return: 0 on success, or error on failure
 *
 */
int fcs_cs_key_object_print(struct fcs_cs_key_object_data *object)
{
	int i;

	if (object == NULL) {
		return -1;
	}

	printf("Print crypto service key object\n");
	printf("    key_id              0x%08x\n", object->key_id);
	printf("    key_type            %d (1:AES, 2:HMAC, 3:ECC NIST P Curve, 4:ECC-BrainPool)\n", object->key_type);
	printf("    key_usage           0x%08x (B0:Enc, B1:Dec, B2:Sign, B3:Verify, B4:Exchange)\n", object->key_usage);
	printf("    key_size            %d bits\n", object->key_size);
	printf("    key_protection      %d\n", object->key_protection);
	printf("    key_wrap_version    %d\n", object->key_wrap_version);

	printf("    data          ");
	for (i = 0; i < (object->key_size/8); i++) {
		if (i & 0xf) {
			printf(" %02x", object->data[i]);
		} else {
			printf("\n        %02x", object->data[i]);
		}
	}
	printf("\n");

	printf("    iv            ");
	for (i = 0; i < FCS_CS_KEY_IV_MAX_SZ; i++) {
		if (i & 0xf) {
			printf(" %02x", object->iv[i]);
		} else {
			printf("\n        %02x", object->iv[i]);
		}
	}
	printf("\n");

	printf("    mac           ");
	for (i = 0; i < FCS_CS_KEY_MAC_MAX_SZ; i++) {
		if (i & 0xf) {
			printf(" %02x", object->mac[i]);
		} else {
			printf("\n        %02x", object->mac[i]);
		}
	}
	printf("\n");

	return 0;
}
