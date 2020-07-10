#
# \copyright
# MIT License
#
# Copyright (c) 2018 Infineon Technologies AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE
#
# \endcopyright
#
# \author Infineon Technologies AG
#

#Include build congiguration, compiler to be used, file name/directory definitions
-include Config.mk

.PHONY: all $(wolfssl) $(sample)

all: $(wolfssl) $(sample)

#Make application note

#Include build congiguration, compiler to be used, file name/directory definitions
-include ../../Config.mk

#Source code root directory from the directory of this make file
ROOT_DIR = ../../

#Bin directory..
BIN_DIR = ./lib

#Header file dependencies
INCLUDES = -I$(ROOT_DIR)examples/optiga/include -I$(ROOT_DIR)externals/wolfssl_linux -I$(ROOT_DIR)optiga/include -I$(ROOT_DIR)optiga/include/optiga -I$(ROOT_DIR)optiga/include/optiga/pal -I$(ROOT_DIR)optiga/include/optiga/ifx_i2c -I$(ROOT_DIR)optiga/include/optiga/common -I$(ROOT_DIR)optiga/include/optiga/comms -I$(ROOT_DIR)pal/raspberry_pi3 -I$(ROOT_DIR)externals/pkcs11/include -I$(ROOT_DIR)unit_test/cunit/include

#Compiler flags
CFLAGS = $(INCLUDES) -g -Wall -c -DWOLFSSL_RPI3_OPTIGA
LDFLAGS	= -L/usr/local/lib
LDLIBS  = -lrt -lm -lpthread -lmbedtls -lmbedx509 -lmbedcrypto -lssl -lcrypto -lcunit

#Binary output file name
TrustM_Sample_Name = OPTIGA_Trust_M1_RPI3_sample

#Actual source code file to be built
SRC = \
$(ROOT_DIR)optiga/crypt/optiga_crypt.c \
$(ROOT_DIR)optiga/util/optiga_util.c \
$(ROOT_DIR)optiga/cmd/optiga_cmd.c \
$(ROOT_DIR)optiga/common/optiga_lib_common.c \
$(ROOT_DIR)optiga/common/optiga_lib_logger.c \
$(ROOT_DIR)optiga/comms/optiga_comms_ifx_i2c.c \
$(ROOT_DIR)optiga/comms/ifx_i2c/ifx_i2c.c \
$(ROOT_DIR)optiga/comms/ifx_i2c/ifx_i2c_config.c \
$(ROOT_DIR)optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c \
$(ROOT_DIR)optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c \
$(ROOT_DIR)optiga/comms/ifx_i2c/ifx_i2c_presentation_layer.c \
$(ROOT_DIR)optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c \
$(ROOT_DIR)pal/raspberry_pi3/pal.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_gpio.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_ifx_i2c_config.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_os_event.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_os_timer.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_i2c.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_logger.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_os_datastore.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_os_lock.c \
$(ROOT_DIR)pal/raspberry_pi3/pal_os_memory.c \
$(ROOT_DIR)pal/pal_crypt_openssl.c \
$(ROOT_DIR)externals/pkcs11/ecdsa_utils.c \
$(ROOT_DIR)externals/pkcs11/pkcs11_trustm.c \
$(ROOT_DIR)examples/optiga/example_optiga_crypt_tls_prf_sha256.c \
$(ROOT_DIR)examples/optiga/usecases/example_pair_host_and_optiga_using_pre_shared_secret.c \
$(ROOT_DIR)unit_test/cunit/c_unit_helper.c \
$(ROOT_DIR)unit_test/test_holder/test_holder_pkcs11.c \
$(ROOT_DIR)unit_test/test_src/ut_optiga_pkcs_init_deinit.c \
$(ROOT_DIR)unit_test/test_src/aws_dev_mode_key_provisioning.c \
$(ROOT_DIR)unit_test/test_src/iot_test_pkcs11.c \
$(ROOT_DIR)unit_test/main.c \

#Make Platform Crypto layer
$(wolfssl):
	$(MAKE) --directory=$@

COBJS = $(SRC:.c=.o)

$(COBJS) : %.o : %.c
	$(CC) $(CFLAGS) $<
	mv *.o $(BIN_DIR)
	
all: $(COBJS) sample

sample:
	$(CC) -o "$(BIN_DIR)/$(TrustM_Sample_Name)" "$(BIN_DIR)/"*.o -L$(BIN_DIR) $(LDLIBS) 



clean:
	$(CLEAN) "$(BIN_DIR)/"*.o
	$(CLEAN) "$(BIN_DIR)/$(TrustM_Sample_Name)"
