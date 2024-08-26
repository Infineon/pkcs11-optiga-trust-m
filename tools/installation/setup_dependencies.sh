#!/bin/bash

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

sudo apt-get update
sudo apt-get install -y cmake libssl-dev libusb-1.0-0-dev xxd
sudo apt-get install -y libcunit1-dev libpthread-stubs0-dev libgpiod-dev
sudo apt-get install -y opensc
