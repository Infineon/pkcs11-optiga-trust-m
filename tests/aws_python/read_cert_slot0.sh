#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-FileCopyrightText: SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

### SLOT 0
chmod +x pd

./pd --slot 0 --label Cert --read-object --type cert --output-file certificates/Slot0CertRead.der

xxd certificates/Slot0CertRead.der

openssl x509 -inform DER -in certificates/Slot0CertRead.der -outform PEM -out certificates/mycert0.pem

openssl x509 -in certificates/mycert0.pem -text -noout
