#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-FileCopyrightText: SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

CA_KEY="certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem"
CA_CERT="certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem"

chmod +x pd

echo "-----> "
set -e

echo "-----> Generate Dummy ECC Private Key"
openssl ecparam -out certificates/dummy_privkey.pem -name prime256v1 -genkey

echo "Server1:-----> Generate CSR"
openssl req -new  -key certificates/dummy_privkey.pem -subj /CN=TrustM_Dev1/O=Infineon/C=SG -out certificates/dummy_csr.csr

echo "Server1:-----> Generate Server certificate by using CA"

./pd --keypairgen --slot 1 --key-type EC:secp256r1

./pd --slot 1 --label PubKey --read-object --type data --output-file certificates/pubkey.der
xxd certificates/pubkey.der

openssl ec -inform DER  -pubin -in certificates/pubkey.der -outform PEM -out certificates/pubkey.pem
cat certificates/pubkey.pem

openssl x509 -req -in certificates/dummy_csr.csr -force_pubkey certificates/pubkey.pem -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out certificates/mycert1.pem

openssl x509 -in certificates/mycert1.pem -text
