# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.5)
include(GNUInstallDirs)
project(optigatrust)

set(TRUSTM_PATH external/optiga-trust-m )
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/examples/utilities/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/examples/optiga/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/config)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/include/cmd)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/include/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/include/comms)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/include/ifx_i2c)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/include/pal)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/external/mbedtls/include)

include_directories(/usr/local/openssl/include)
# Add sources for Trust M Core and Platform Abstraction Layer
# Add sources
set(TRUSTM_CORE_SRCS 
    ${TRUSTM_PATH}/src/crypt/optiga_crypt.c
    ${TRUSTM_PATH}/src/util/optiga_util.c
    ${TRUSTM_PATH}/src/cmd/optiga_cmd.c
    ${TRUSTM_PATH}/src/common/optiga_lib_common.c
    #~ ${TRUSTM_PATH}/src/common/log.c
    #${TRUSTM_PATH}/src/common/optiga_lib_logger.c
    ${TRUSTM_PATH}/src/comms/ifx_i2c/ifx_i2c.c
    ${TRUSTM_PATH}/src/comms/ifx_i2c/ifx_i2c_config.c
    ${TRUSTM_PATH}/src/comms/ifx_i2c/ifx_i2c_data_link_layer.c
    ${TRUSTM_PATH}/src/comms/ifx_i2c/ifx_i2c_physical_layer.c
    ${TRUSTM_PATH}/src/comms/ifx_i2c/ifx_i2c_presentation_layer.c
    ${TRUSTM_PATH}/src/comms/ifx_i2c/ifx_i2c_transport_layer.c
    ${TRUSTM_PATH}/src/comms/optiga_comms_ifx_i2c.c
    ${TRUSTM_PATH}/external/mbedtls/library/sha256.c
    ${TRUSTM_PATH}/external/mbedtls/library/platform_util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/utilities/log.c    
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/utilities/pkcs11_trustm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/utilities/ecdsa_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/utilities/optiga_lib_logger.c

)

include(${CMAKE_CURRENT_SOURCE_DIR}/linux_libusb.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/linux_i2c.cmake)


