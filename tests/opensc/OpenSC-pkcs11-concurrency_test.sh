#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-FileCopyrightText: SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

chmod +x pd
rm *.sig *.log 2> /dev/null
set -e



clear
echo "Paralell process test examples:"
echo "=================================================="
echo "======>Show PKCS#11 module/library info"	
./pd --show-info


echo "======>Generate ECC key pair"	
./pd --slot 1 --keypairgen --key-type EC:secp256r1

./pd --slot 2 --keypairgen --key-type EC:secp384r1


echo "======>Hash data"	
echo "01234567890123456789012345678901234567890123456789" > data.in


./pd --hash  --hash-algorithm SHA256 --input-file data.in --output-file data.sha
xxd data.sha 

for i in $(seq 1 5); do 
echo "======>ECDSA signature (by ID)"	
./pd --slot 1 --sign --mechanism ECDSA --input-file data.sha --output-file Slot1prvkey.sig &
P1=$!

./pd --slot 2 --sign --mechanism ECDSA --input-file data.sha --output-file Slot2prvkey.sig &
P2=$!

wait $P1 $P2

echo "======>Verify ECDSA signature (by ID)"
./pd --slot 1 --verify --mechanism ECDSA --input-file data.sha --signature-file Slot1prvkey.sig &
P1=$!

./pd --slot 2 --verify --mechanism ECDSA --input-file data.sha --signature-file Slot2prvkey.sig &
P2=$!

done 
 
wait $P1 $P2
echo ==== Finished - OK ====
