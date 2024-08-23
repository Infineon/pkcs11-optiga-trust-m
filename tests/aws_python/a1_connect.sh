#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-FileCopyrightText: SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

#######################################################################################
# AWS IoT configuration
#######################################################################################
export DEVICE_CERT_PATH=certificates/mycert1.pem
export AWS_CERT_PATH=certificates/AmazonRootCA1.pem

export IOT_CORE_ENDPOINT=a2kfkheds2p7dx-ats.iot.us-west-2.amazonaws.com
export CLIENT_ID=arn:aws:iot:us-west-2:767398033664:thing/Rpi-TrustM-PKCS11

#######################################################################################
# PKCS#11 library configuration
#######################################################################################

####################
# Regular non-spy mode
####################
export PKCS11_MODULE=liboptigatrust-i2c-linux-pkcs11.so
####################
# PKCS#11 spy mode
####################
#~ export PKCS11_MODULE=/usr/lib/pkcs11-spy.so
#~ export PKCS11SPY=liboptigatrust-i2c-linux-pkcs11.so
#~ export OPENSC_DEBUG=9
#~ export PKCS11SPY_OUTPUT=pkcs11-spy-aws-generate-cert.log
#~ pkcs11-tool --module $PKCS11_MODULE -v $@
#######################################################################################

if [ -e $AWS_CERT_PATH ]
then
    echo "AMZ CA cert ok"
else
    echo "Fetch AMZ CA cert from url"
    wget -P certificates https://www.amazontrust.com/repository/AmazonRootCA1.pem
fi

python3 connect_aws.py \
--pcks11lib $PKCS11_MODULE \
--slot 1 \
--keylabel PrvKey \
--certpath $DEVICE_CERT_PATH \
--endpoint $IOT_CORE_ENDPOINT \
--cafile $AWS_CERT_PATH \
--clientid $CLIENT_ID
