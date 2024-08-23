<!--
SPDX-FileCopyrightText: 2024 Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

# Quick navigation

- [Quick navigation](#quick-navigation)
- [PKCS#11 Interface implementation for OPTIGA™ Trust M Host library for C](#pkcs11-interface-implementation-for-optiga-trust-m-host-library-for-c)
- [Preparing the Environment](#preparing-the-environment)
  - [Setting up the Linux environment on Raspberry Pi](#setting-up-the-linux-environment-on-raspberry-pi)
  - [Hardware connections between OPTIGA™ Trust M and Raspberry Pi](#hardware-connections-between-optiga-trust-m-and-raspberry-pi)
- [Building System Test Project for PKCS#11](#building-system-test-project-for-pkcs11)
  - [Get the latest version of PKCS#11 implementation with OPTIGA™ Trust M](#get-the-latest-version-of-pkcs11-implementation-with-optiga-trust-m)
  - [Submodule MbedTLS](#submodule-mbedtls)
  - [Build PKCS#11 library with OPTIGA™ Trust M](#build-pkcs11-library-with-optiga-trust-m)

# PKCS#11 Interface implementation for </br>OPTIGA™ Trust M Host library for C

PKCS#11 is a Public-Key Cryptography Standard that defines a standard method to access cryptographic services from tokens/devices such as hardware security modules (HSM), smart cards etc. In this project we intend to use a OPTIGA™ Trust M device as the cryptographic token.

# Preparing the Environment

This repository tests runs on a Raspberry PI. The rapsberry PI used is running on Raspbian OS.

To prepare and install Raspbian OS in a raspberry PI, please refer to the official doumentation [here](https://www.raspberrypi.com/documentation/computers/getting-started.html).

## Setting up the Linux environment on Raspberry Pi

Once the raspberry PI is set up and ready to use, the I2C interface needs to be enabled. this interface will be used to communicate with OPTIGA™ Trust M device.

Run the command below in the terminal console.
```console
sudo raspi-config
```
* Navigate to Interfacing Options.
* Select I2C and hit enter.
* When the window to enable the I2C interface is appeared select yes.
* Finish the configuration window.


## Hardware connections between OPTIGA™ Trust M and Raspberry Pi

Two hardware connexions types:

1. **I2C Connection**
    Below table shows the I2C connection between the [OPTIGA™ Trust M](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-security-optiga-m/) and Raspberry Pi(RPI).

| No       			| Description		| RPI Pin # | Pin Description |
| :-------------: | :----------: | :-----------: | :-----------: |
| 1| I2C SCL  | 5 |SCL1, I2C    |
| 2| I2C SDA   | 3 | SDA1, I2C    |
| 3 | VCC   | 17 | 3V3 |
| 4 | GND   | 9 | GND    |

2. **[USB Dongle](./docs/schematics/V_1_1)**. In this case you just need to plug it into one of available USB slots on your Raspberry Pi board


# Building System Test Project for PKCS#11

## Get the latest version of PKCS#11 implementation with OPTIGA™ Trust M

	git clone --recurse-submodules https://github.com/Infineon/pkcs11-optiga-trust-m

## Submodule MbedTLS

MbedTLS submodule needs to be clonned manually.

please navigate to the folder external/optiga-trust-m and run git submodule command as shown here :

```
cd external/optiga-trust-m
git submodule update --init
cd ../..
```

## Build PKCS#11 library with OPTIGA™ Trust M

To Install system dependencies and build the project with installation scripts, follow the steps below.

> if not installed, A tool might be needed to run the next script in Linux environment. please install dos2unix tool and apply it to the script before running the script.
```
sudo apt install dos2unix
```

1. Navigate to [tools/installation](tools/installation/) folder.

```console
cd tools/installation
```

2. Run the **setup_dependencies.sh** shell script provided. This will install all dependencies needed by the PKCS#11 project.

```console
chmod +x setup_dependencies.sh
dos2unix setup_dependencies.sh
./setup_dependencies.sh
```

3. Run the **install_shared_lib.sh** shell script provide will compile and install the shared libraries into the system.

```console
chmod +x install_shared_lib.sh
dos2unix install_shared_lib.sh
./install_shared_lib.sh
```

4. Go to [OpenSC folder](./tests/opensc) to run examples in script **OpenSC-pkcs11-tool-commands.sh**


From root folder :

```console
cd tests/opensc
chmod +x OpenSC-pkcs11-tool-commands.sh
dos2unix OpenSC-pkcs11-tool-commands.sh
./OpenSC-pkcs11-tool-commands.sh
```

To clean the files generated by the execution of OpenSC-pkcs11-tool-commands.sh, the script clean.sh can be used :

```console
chmod +x clean.sh
dos2unix clean.sh
./clean.sh
```





