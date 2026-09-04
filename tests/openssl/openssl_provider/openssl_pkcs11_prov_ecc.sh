#!/bin/bash

# SPDX-FileCopyrightText: 2026 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

chmod +x pd
dos2unix pd
#~ rm *.log

set -e
declare -i ErrorCount=0

clear

echo "Worked pkcs11 provider command examples for ECC256:"
echo "=================================================="

echo "======> Detecting OpenSSL Version"
OPENSSL_VERSION=$(openssl version | awk '{print $2}')
echo "Detected OpenSSL Version: $OPENSSL_VERSION"
echo

#~ echo "======>List slots with tokens"	
#~ ./pd --list-token-slots

#~ echo "======>List supported mechanisms"
#~ ./pd --list-mechanisms --slot 1

#~ echo "======>Show objects"
#~ ./pd --list-objects --slot 1

echo =================================================================================== 
echo "Setting up the slot "
echo =================================================================================== 
echo
echo "======>Generate ECC key pair"	
./pd --slot 1 --keypairgen --key-type EC:secp256r1
./pd --slot 1 --label PubKey --read-object --type data --output-file Token1PubKey.der
openssl ec -pubin -inform DER -in Token1PubKey.der -out Token1PubKey.pem

echo "======>Hash data"	
echo "01234567890123456789012345678901234567890123456789" > test.txt	
./pd --hash  --hash-algorithm SHA256 --input-file test.txt --output-file test.sha
xxd test.sha 

echo
echo =================================================================================== 
echo "Use PKCS#11 Provider "
echo =================================================================================== 
echo
if [[ $OPENSSL_VERSION == 3.* ]]; then
	echo ------------------------------------------------------------------------------------
	echo "======>Read out the Public Key"
	echo ------------------------------------------------------------------------------------
	OPENSSL_CONF=openssl_pkcs11.cnf openssl pkey -provider pkcs11 -in "pkcs11:token=Token1" -pubin -pubout -text

	echo ------------------------------------------------------------------------------------
	echo "======>Generate CSR"
	echo ------------------------------------------------------------------------------------
	OPENSSL_CONF=openssl_pkcs11.cnf openssl req -new -provider pkcs11 -key "pkcs11:token=Token1" -out new_device.csr -subj "/CN=TrustM"
	cat new_device.csr
	echo ------------------------------------------------------------------------------------
	echo "======>Sign with private key"	
	echo ------------------------------------------------------------------------------------
	OPENSSL_CONF=openssl_pkcs11.cnf openssl dgst -provider pkcs11 -sign "pkcs11:token=Token1" -out signature.bin -sha256 test.txt
	echo  "The signature is:"
	xxd -p signature.bin

	echo ------------------------------------------------------------------------------------
	echo "======>Verify signature"	
	echo ------------------------------------------------------------------------------------

	OPENSSL_CONF=openssl_pkcs11.cnf openssl dgst -provider pkcs11 -verify "pkcs11:token=Token1" -signature signature.bin -sha256 test.txt

else
    echo "Unsupported OpenSSL version: $OPENSSL_VERSION, require version 3.*"
    exit 1
fi

if [ $ErrorCount -ne 0 ]; then 
 echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
 echo Verification errors: $ErrorCount
 echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
 (exit 1)
fi
echo ==== Finished - OK ====
