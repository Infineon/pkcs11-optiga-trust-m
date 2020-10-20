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
PKCS11_INCLUDE_DIR = ../../../optiga-trust-m/examples/utilities
#Bin directory..
BIN_DIR = ./lib

#Header file dependencies
INCLUDES = -I$(PKCS11_INCLUDE_DIR)/include -I$(ROOT_DIR)cunit_framework/include

#Compiler flags
CFLAGS = $(INCLUDES) -g -Wall -c -DWOLFSSL_RPI3_OPTIGA
LDFLAGS	= -L/usr/local/lib
LDLIBS  = -lrt -lm -lpthread -lssl -lcrypto -lcunit -loptigatrust-i2c-linux-pkcs11

#Binary output file name
TrustM_Sample_Name = OPTIGA_Trust_M_PKCS11_Test

#Actual source code file to be built
SRC = \
$(ROOT_DIR)cunit_framework/c_unit_helper.c \
$(ROOT_DIR)test/test_holder_pkcs11.c \
$(ROOT_DIR)test/st_C_test_utility.c \
$(ROOT_DIR)test/st_C_Initialize_Finalize.c \
$(ROOT_DIR)test/st_C_GenerateRandom.c \
$(ROOT_DIR)test/st_C_GenerateKeyPair.c \
$(ROOT_DIR)test/st_C_Sign.c \
$(ROOT_DIR)test/st_C_Verify.c \
$(ROOT_DIR)test/st_C_Encrypt_Decrypt.c \
$(ROOT_DIR)test/st_C_Digest.c \
$(ROOT_DIR)test/st_C_GetTokenInfo.c \
$(ROOT_DIR)test/st_C_GetMechanismInfo.c \
$(ROOT_DIR)test/st_C_GetAttributeValue.c \
$(ROOT_DIR)test/st_C_FindObjects.c \
$(ROOT_DIR)main/main.c \

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
