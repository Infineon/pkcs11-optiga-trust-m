#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

chmod +x pd
dos2unix pd
#~ rm *.log

set -e
declare -i ErrorCount=0

clear

echo "Worked pkcs11 engine command examples for RSA2048:"
echo "=================================================="

echo "======> Detecting OpenSSL Version"
OPENSSL_VERSION=$(openssl version | awk '{print $2}')
echo "Detected OpenSSL Version: $OPENSSL_VERSION"

#~ echo "======>List slots with tokens"	
#~ ./pd --list-token-slots

#~ echo "======>List supported mechanisms"
#~ ./pd --list-mechanisms --slot 4

#~ echo "======>Show objects"
#~ ./pd --list-objects --slot 4

echo "======>Generate RSA key pair"	
./pd --slot 4 --keypairgen --key-type RSA:2048
./pd --slot 4 --label PubKey --read-object --type data --output-file Slot4PubKey.der
xxd Slot4PubKey.der

echo "======>Hash data"	
echo "01234567890123456789012345678901234567890123456789" > test.txt	
./pd --hash  --hash-algorithm SHA256 --input-file test.txt --output-file test.sha
xxd test.sha

if [[ $OPENSSL_VERSION == 3.* ]]; then
	echo -e "\n======>Read out the Public Key for Token4"	
	OPENSSL_CONF=openssl3_pkcs11.cnf openssl pkey -engine pkcs11 -in "pkcs11:token=Token4" -pubin -pubout -text -inform engine

	echo -e "\n======>Generate CSR"
	OPENSSL_CONF=openssl3_pkcs11.cnf openssl req -new -engine pkcs11 -key "pkcs11:token=Token4" -keyform engine -out new_device.csr -subj "/CN=TrustM"
	cat new_device.csr

	echo -e "\n======>RSA sign"	
	OPENSSL_CONF=openssl3_pkcs11.cnf openssl dgst -engine pkcs11 -sign "pkcs11:token=Token4" -keyform engine -out Slot4prvkey.sig -sha256 test.txt
	echo -n "The text is : " 
	cat test.txt
	echo "The singature is : "
	xxd -p Slot4prvkey.sig

	echo -e "\n======>Verify signature"	
	OPENSSL_CONF=openssl3_pkcs11.cnf openssl dgst -engine pkcs11 -verify "pkcs11:token=Token4" -keyform engine -signature Slot4prvkey.sig -sha256 test.txt
	
elif [[ $OPENSSL_VERSION == 1.1.* ]]; then

	echo -e "\n======>Read out the Public Key for Token4"	
	OPENSSL_CONF=openssl1_pkcs11.cnf openssl pkey -engine pkcs11 -in "pkcs11:token=Token4" -pubin -pubout -text -inform engine

	echo -e "\n======>Generate CSR"
	OPENSSL_CONF=openssl1_pkcs11.cnf openssl req -new -engine pkcs11 -key "pkcs11:token=Token4" -keyform engine -out new_device.csr -subj "/CN=TrustM"
	cat new_device.csr

	echo -e "\n======>RSA sign"	
	OPENSSL_CONF=openssl1_pkcs11.cnf openssl dgst -engine pkcs11 -sign "pkcs11:token=Token4" -keyform engine -out Slot4prvkey.sig -sha256 test.txt
	echo -n "The text is : " 
	cat test.txt
	echo "The singature is : "
	xxd -p Slot4prvkey.sig

	echo -e "\n======>Verify signature"	
	OPENSSL_CONF=openssl1_pkcs11.cnf openssl dgst -engine pkcs11 -verify "pkcs11:token=Token4" -keyform engine -signature Slot4prvkey.sig -sha256 test.txt
else
    echo "Unsupported OpenSSL version: $OPENSSL_VERSION"
    exit 1
fi
if [ $ErrorCount -ne 0 ]; then 
 echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
 echo Verification errors: $ErrorCount
 echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
 (exit 1)
fi
echo ==== Finished - OK ====
