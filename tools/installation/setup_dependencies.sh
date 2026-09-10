#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

sudo apt-get update
sudo apt-get install -y cmake libssl-dev libusb-1.0-0-dev xxd pkg-config
sudo apt-get install -y libcunit1-dev libpthread-stubs0-dev libgpiod-dev
sudo apt-get install -y opensc libengine-pkcs11-openssl
sudo apt-get install -y pkcs11-provider
