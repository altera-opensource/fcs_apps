Example Usage:

For creating a HPS Image Certificate, you'll need an HPS image because
part of the certificate is the SHA384 hash over the HPS image. The
certificate is concatenated onto the padded 4 byte boundary HPS image.

	./fcs_prepare --hps_cert u-boot-dtb.img
	results are in unsigned_cert.ccert

	after signing this image, use the finish command
	./fcs_prepare --finish signed_cert.ccert --imagefile u-boot-dtb.img
	the concatenated result is stored in hps_image_signed.vab

For creating a Counter Set command

	./fcs_prepare --counter_set -s 2 -c 60 [--base]
	Select counter 2, set counter to 60
	if --base && counter == 1, the value in -c will set the base
	of the big counter, otherwise it is an incremental counter set.
	results are in unsigned_cert.ccert

For creating a Key cancellation command

	./fcs_prepare --key -k 0 -i 5 [-r <roothash filename if -k == 0>]
	Key type = User, key id = 5, if key_id = -1, cancel owner root hash
	roothash is only valid if key_type (-k) is User(0).
	results are in unsigned_cert.ccert

To see verbose output, use -v at the end
