Build on the Linux x86 host for ARM64.
CROSS_COMPILE must be set otherwise it will build for x86.

$ export CROSS_COMPILE=aarch64-linux-gnu-; export ARCH=arm64

$ make clean; make all && sudo cp fcs_client ~/software/filesystem/arm64_rootfs/ROOTFS_AGILEX/home/root/tools/
