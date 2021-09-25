This is the repository for the application source code necessary for FPGA
crypto service.

This repository includes software from several sources under a collection of
compatible open source licenses; refer to the specific copyright/license
embedded in each source file.

fcs_client is the Intel SoC FPGA Linux user space application which provides
the command line interface for user to exercise the FPGA crypto service.
For example, read back the provision data, data encryption and decryption,
generate random number, etc.

Build on the Linux x86 host for ARM64.
CROSS_COMPILE must be set otherwise it will build for x86.

$ export CROSS_COMPILE=aarch64-linux-gnu-; export ARCH=arm64

$ make clean; make all && sudo cp fcs_client ~/software/filesystem/arm64_rootfs/ROOTFS_AGILEX/home/root/tools/
