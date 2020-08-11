cmake_minimum_required(VERSION 3.5)
include(GNUInstallDirs)
project(optigatrust)

set(TRUSTM_PATH ./optiga-trust-m )
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/examples/utilities/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/examples/optiga/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${TRUSTM_PATH}/optiga/include)
include_directories(/usr/local/openssl/include)
# Add sources for Trust M Core and Platform Abstraction Layer
# Add sources
set(TRUSTM_CORE_SRCS 
    ${TRUSTM_PATH}/optiga/crypt/optiga_crypt.c
    ${TRUSTM_PATH}/optiga/util/optiga_util.c
    ${TRUSTM_PATH}/optiga/cmd/optiga_cmd.c
    ${TRUSTM_PATH}/optiga/common/optiga_lib_common.c
    ${TRUSTM_PATH}/optiga/common/optiga_lib_logger.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_config.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_presentation_layer.c
    ${TRUSTM_PATH}/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c
    ${TRUSTM_PATH}/optiga/comms/optiga_comms_ifx_i2c.c
    ${TRUSTM_PATH}/examples/utilities/pkcs11_trustm.c
    ${TRUSTM_PATH}/examples/utilities/ecdsa_utils.c
    ${TRUSTM_PATH}/examples/optiga/usecases/example_pair_host_and_optiga_using_pre_shared_secret.c
)

include(${CMAKE_CURRENT_SOURCE_DIR}/linux_i2c.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/linux_libusb.cmake)


