#!/bin/bash

CURDIR=`pwd`
HOST_ARCH=$(echo $(arch))

if [ "$HOST_ARCH" = "aarch64" ];then
	HOST_CROSS=
	echo $CURDIR
else
	HOST_CROSS=aarch64-linux-gnu-
fi

# This expects that this is place as a first level folder relative to the other
# OP-TEE folder in a setup using default repo configuration as described by the
# documentation in optee_os (README.md)
ROOT=${PWD}
ROOT=`dirname $ROOT`

# Path to the toolchain
#export PATH=${ROOT}/toolchains/aarch32/bin:$PATH

# Path to the TA-DEV-KIT coming from optee_os
export TA_DEV_KIT_DIR=${ROOT}/out/data/link/export-ta_arm64

# Path to the client library (GP Client API)
export TEEC_EXPORT=${ROOT}/out/data/link/export/usr

export PLATFORM=ft

# Toolchain prefix for user space code (normal world)
HOST_CROSS_COMPILE=$HOST_CROSS
# Build the host application
cd $CURDIR/host
#make CROSS_COMPILE=$HOST_CROSS_COMPILE $@

# Toolchain prefix for the Trusted Applications
TA_CROSS_COMPILE=$HOST_CROSS
# Build the Trusted Application
cd $CURDIR/ta
# make O=$CURDIR/ta/out CROSS_COMPILE=$TA_CROSS_COMPILE CFG_TEE_TA_LOG_LEVEL=4 $@
make O=$CURDIR/ta/out CROSS_COMPILE=$TA_CROSS_COMPILE $@

cp $CURDIR/host/scto $CURDIR/../out/data/bin/ -f
cp $CURDIR/ta/out/*.ta $CURDIR/../out/data/optee_armtz/ -f
