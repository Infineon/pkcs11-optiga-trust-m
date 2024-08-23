#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-FileCopyrightText: SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

#~ rm -d -r -f  linux-optiga-trust*

#~ rm *.csr
#~ rm *.pem
#~ rm *.log
#~ rm *.bin
#~ rm *.der

# Delete specific file types while excluding certain files
find . -type f \( -name "*.csr" -o -name "*.log" -o -name "*.bin" -o -name "*.der" -o -name "*.pem" \) ! -name "OPTIGA_Trust_M_Infineon_Test_CA_Key.pem" ! -name "OPTIGA_Trust_M_Infineon_Test_CA.pem" ! -name "AmazonRootCA1.pem" -exec rm {} +

# Explanation for the additions:
# - ! -name "OPTIGA_Trust_M_Infineon_Test_CA_Key.pem": Excludes "OPTIGA_Trust_M_Infineon_Test_CA_Key.pem" from deletion
# - ! -name "OPTIGA_Trust_M_Infineon_Test_CA.pem": Excludes "OPTIGA_Trust_M_Infineon_Test_CA.pem" from deletion
# - ! -name "AmazonRootCA1.pem": Excludes "AmazonRootCA1.pem" from deletion
# - find . -type f: Find all files in the current directory
# - \( -name "*.csr" -o -name "*.log" -o ... \): Matches files ending with .csr, .log, etc.
# - -exec rm {} +: For all matching files, execute 'rm' to delete them
