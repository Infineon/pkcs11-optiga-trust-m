#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

chmod +x pd
dos2unix pd

export IFX_CERT_PATH=certificates/OPTIGA_Trust_M_Infineon_Test_CA.pem
export IFX_CERT_KEY=certificates/OPTIGA_Trust_M_Infineon_Test_CA_Key.pem

set -e
declare -i ErrorCount=0

clear
echo "Worked OpenSC pkcs11-tool command examples:"
echo "=================================================="
echo "======>Show PKCS#11 module/library info"	
./pd --show-info

echo "======>List available slots"	
./pd --list-slots

echo "======>List slots with tokens"	
./pd --list-token-slots

echo "======>List supported mechanisms"
./pd --list-mechanisms
./pd --list-mechanisms --slot 1
./pd --list-mechanisms --slot 2
./pd --list-mechanisms --slot 3
#./pd --list-mechanisms --slot 4 - !!!JC - RSA not finished
#./pd --list-mechanisms --slot 5 - !!!JC - RSA not finished

echo "======>Show objects"
./pd --list-objects --slot 0
./pd --list-objects --slot 1
./pd --list-objects --slot 2
./pd --list-objects --slot 3
# ./pd --list-objects --slot 4 - !!!JC - RSA not finished
# ./pd --list-objects --slot 5 - !!!JC - RSA not finished

echo "======>list only certificates"	
./pd --slot 0 --list-objects --type cert
./pd --slot 1 --list-objects --type cert
./pd --slot 2 --list-objects --type cert
./pd --slot 3 --list-objects --type cert

./pd --slot 0 --list-objects --type privkey
./pd --slot 1 --list-objects --type privkey
./pd --slot 2 --list-objects --type privkey
./pd --slot 3 --list-objects --type privkey

./pd --slot 0 --list-objects --type pubkey
./pd --slot 1 --list-objects --type pubkey
./pd --slot 2 --list-objects --type pubkey
./pd --slot 3 --list-objects --type pubkey

echo "======>Generate random on chip"	
./pd --generate-random 8 --output-file rand8.bin
xxd rand8.bin

./pd --generate-random 16 --output-file rand16.bin
xxd rand16.bin

./pd --generate-random 32 --output-file rand32.bin
xxd rand32.bin

echo "======>Read IFX PubKey"
./pd --slot 0 --label PubKey --read-object --type data --output-file Slot0PubKey.der

echo "-----> Generate Dummy ECC Private Key"
openssl ecparam -out Slot1dummy_privkey.pem -name prime256v1 -genkey
openssl ec -in Slot1dummy_privkey.pem -pubout -out Slot1dummy_pubkey.pem
openssl pkey -in Slot1dummy_pubkey.pem -pubin -outform DER -out Slot1dummy_pubkey.der

openssl ecparam -out Slot2dummy_privkey.pem -name secp384r1 -genkey
openssl ec -in Slot2dummy_privkey.pem -pubout -out Slot2dummy_pubkey.pem
openssl pkey -in Slot2dummy_pubkey.pem -pubin -outform DER -out Slot2dummy_pubkey.der

openssl ecparam -out Slot3dummy_privkey.pem -name secp521r1 -genkey
openssl ec -in Slot3dummy_privkey.pem -pubout -out Slot3dummy_pubkey.pem
openssl pkey -in Slot3dummy_pubkey.pem -pubin -outform DER -out Slot3dummy_pubkey.der

echo "Server1:-----> Generate CSR"
openssl req -new  -key Slot1dummy_privkey.pem -subj /CN=TrustM_Dev1/O=Infineon/C=SG -out Slot1dummy_csr.csr
openssl req -new  -key Slot2dummy_privkey.pem -subj /CN=TrustM_Dev1/O=Infineon/C=SG -out Slot2dummy_csr.csr
openssl req -new  -key Slot3dummy_privkey.pem -subj /CN=TrustM_Dev1/O=Infineon/C=SG -out Slot3dummy_csr.csr

echo "Server1:-----> Generate Server cetificate by using CA"

echo "======>Generate ECC key pair"	
./pd --slot 1 --keypairgen --key-type EC:secp256r1
./pd --slot 1 --label PubKey --read-object --type data --output-file Slot1PubKey.der
xxd Slot1PubKey.der

./pd --slot 2 --keypairgen --key-type EC:secp384r1
./pd --slot 2 --label PubKey --read-object --type data --output-file Slot2PubKey.der
xxd Slot2PubKey.der

./pd --slot 3 --keypairgen --key-type EC:secp521r1
./pd --slot 3 --label PubKey --read-object --type data --output-file Slot3PubKey.der
xxd Slot3PubKey.der

#echo "3059301306072A8648CE3D020106082A8648CE3D030107"$(xxd -ps -c 68 Slot1PubKeyF1D1.bin) | xxd -r -p > Slot1PubKeyF1D1.der
#echo "3076301006072A8648CE3D020106052B81040022"$(xxd -ps -c 100 Slot2PubKeyF1D2.bin) | xxd -r -p > Slot2PubKeyF1D2.der
#echo "30819B301006072A8648CE3D020106052B81040023"$(xxd -ps -c 137 Slot3PubKeyF1D3.bin) | xxd -r -p > Slot3PubKeyF1D3.der

openssl ec -inform DER  -pubin -in Slot1PubKey.der  -outform PEM -out Slot1PubKey.pem
cat Slot1PubKey.pem

openssl ec -inform DER  -pubin -in Slot2PubKey.der  -outform PEM -out Slot2PubKey.pem
cat Slot2PubKey.pem

openssl ec -inform DER  -pubin -in Slot3PubKey.der  -outform PEM -out Slot3PubKey.pem
cat Slot3PubKey.pem

openssl x509 -req -in Slot1dummy_csr.csr -force_pubkey Slot1PubKey.pem -CA $IFX_CERT_PATH -CAkey $IFX_CERT_KEY -CAcreateserial -out Slot1Cert.pem
openssl x509 -in Slot1Cert.pem -text

openssl x509 -req -in Slot2dummy_csr.csr -force_pubkey Slot2PubKey.pem -CA $IFX_CERT_PATH -CAkey $IFX_CERT_KEY -CAcreateserial -out Slot2Cert.pem
openssl x509 -in Slot2Cert.pem -text

openssl x509 -req -in Slot3dummy_csr.csr -force_pubkey Slot3PubKey.pem -CA $IFX_CERT_PATH -CAkey $IFX_CERT_KEY -CAcreateserial -out Slot3Cert.pem
openssl x509 -in Slot3Cert.pem -text

#convert back from PEM to DER before writing certificates 
openssl x509 -outform der -in Slot1Cert.pem -out Slot1Cert.der
openssl x509 -outform der -in Slot2Cert.pem -out Slot2Cert.der
openssl x509 -outform der -in Slot3Cert.pem -out Slot3Cert.der

#echo "======>Read current certificates E0E0...E0E3"	
#./pd --slot 0 --id E0E0 --read-object --type cert --output-file Slot0CertE0E0.der
#./pd --slot 1 --id E0E1 --read-object --type cert --output-file Slot1CertE0E1.der
#./pd --slot 2 --id E0E2 --read-object --type cert --output-file Slot2CertE0E2.der
#./pd --slot 3 --id E0E3 --read-object --type cert --output-file Slot3CertE0E3.der
#./pd --slot-index 0 --id E0E0 --read-object --type cert --output-file Slot0CertE0E0.der

echo "======>Write certificates"	
echo "---> Write/verify cert"	
./pd --slot 1 --label Cert --write-object Slot1Cert.der --type cert
./pd --slot 1 --label Cert --read-object --type cert --output-file Slot1CertRead.der
cmp -l Slot1Cert.der Slot1CertRead.der && echo Slot 1 certificate verified OK || ((ErrorCount=$ErrorCount+1))

./pd --slot 2 --label Cert --write-object Slot2Cert.der --type cert
./pd --slot 2 --label Cert --read-object --type cert --output-file Slot2CertRead.der
cmp -l Slot2Cert.der Slot2CertRead.der && echo Slot 2 certificate verified OK || ((ErrorCount=$ErrorCount+1))

./pd --slot 3 --label Cert --write-object Slot3Cert.der --type cert
./pd --slot 3 --label Cert --read-object --type cert --output-file Slot3CertRead.der
cmp -l Slot3Cert.der Slot3CertRead.der && echo Slot 3 certificate verified OK || ((ErrorCount=$ErrorCount+1))

echo "======>Hash data"	
echo "01234567890123456789012345678901234567890123456789" > data.in	
./pd --hash  --hash-algorithm SHA256 --input-file data.in --output-file data.sha
xxd data.sha 
 
echo "======>ECDSA signature (by ID)"	
./pd --slot 1 --sign --mechanism ECDSA --input-file data.sha --output-file Slot1prvkey.sig
xxd Slot1prvkey.sig

./pd --slot 2 --sign --mechanism ECDSA --input-file data.sha --output-file Slot2prvkey.sig
xxd Slot2prvkey.sig

./pd --slot 3 --sign --mechanism ECDSA --input-file data.sha --output-file Slot3prvkey.sig
xxd Slot3prvkey.sig
 
echo "======>Verify ECDSA signature (by ID)"
./pd --slot 1 --verify --mechanism ECDSA --input-file data.sha --signature-file Slot1prvkey.sig
./pd --slot 2 --verify --mechanism ECDSA --input-file data.sha --signature-file Slot2prvkey.sig
./pd --slot 3 --verify --mechanism ECDSA --input-file data.sha --signature-file Slot3prvkey.sig
 
echo "======>ECDSA signature (by slot)"	
./pd --slot 1 --sign --mechanism ECDSA --input-file data.sha --output-file Slot1prvkey.sig
xxd Slot1prvkey.sig

./pd --slot 2 --sign --mechanism ECDSA --input-file data.sha --output-file Slot2prvkey.sig
xxd Slot2prvkey.sig

./pd --slot 3 --sign --mechanism ECDSA --input-file data.sha --output-file Slot3prvkey.sig
xxd Slot3prvkey.sig
 
echo "======>Verify ECDSA signature (by slot)"	
./pd --slot 1 --verify --mechanism ECDSA --input-file data.sha --signature-file Slot1prvkey.sig
./pd --slot 2 --verify --mechanism ECDSA --input-file data.sha --signature-file Slot2prvkey.sig
./pd --slot 3 --verify --mechanism ECDSA --input-file data.sha --signature-file Slot3prvkey.sig

if [ $ErrorCount -ne 0 ]; then 
 echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
 echo Verification errors: $ErrorCount
 echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
 (exit 1)
fi
echo ==== Finished - OK ====
