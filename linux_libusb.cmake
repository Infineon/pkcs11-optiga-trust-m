# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

# Check for required Libraries
if(UNIX)
	find_path(LIBUSB_INCLUDE_DIR NAMES libusb.h PATH_SUFFIXES "include" "libusb" "libusb-1.0")
	find_path(LIBUDEV_INCLUDE_DIR NAMES libudev.h PATH_SUFFIXES "include")
	find_library(HAS_LIBUSB usb-1.0)
	if(NOT HAS_LIBUSB AND LIBUSB_INCLUDE_DIR)
		message(FATAL_ERROR, "Missing Build Dependencies for TRUST_PAL_LIBUSB - install libusb-1.0-0-dev")	
	endif()

	set(TARGET_LIBUSB_SHLIB ${PROJECT_NAME}-libusb-linux-pkcs11)

	set(TRUSTM_LIBUSB_SRCS 
		${TRUSTM_PATH}/extras/pal/libusb/pal_common.c
		${TRUSTM_PATH}/extras/pal/libusb/pal.c
		${TRUSTM_PATH}/extras/pal/libusb/pal_gpio.c
		${TRUSTM_PATH}/extras/pal/libusb/pal_i2c.c
		${TRUSTM_PATH}/extras/pal/libusb/pal_ifx_usb_config.c
		${TRUSTM_PATH}/extras/pal/libusb/pal_logger.c
		${TRUSTM_PATH}/extras/pal/libusb/pal_os_datastore.c
		${TRUSTM_PATH}/extras/pal/libusb/pal_os_event.c
		${TRUSTM_PATH}/extras/pal/libusb/pal_os_lock.c
		${TRUSTM_PATH}/extras/pal/libusb/pal_os_memory.c 
		${TRUSTM_PATH}/extras/pal/libusb/pal_os_timer.c
		${TRUSTM_PATH}/extras/pal/pal_crypt_openssl.c
	)
	set(TRUSTM_LIBUSB_INC ${TRUSTM_PATH}/extras/pal/libusb/include)
	add_library(${TARGET_LIBUSB_SHLIB} SHARED ${TRUSTM_CORE_SRCS} ${TRUSTM_LIBUSB_SRCS})
	target_include_directories(${TARGET_LIBUSB_SHLIB}  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
													   ${LIBUSB_INCLUDE_DIR}
													   ${TRUSTM_LIBUSB_INC})
	if(ENABLE_DEBUG)
		message("-----> USB DEBUG mode")
		target_compile_definitions(${TARGET_LIBUSB_SHLIB} PRIVATE -DIFX_I2C_FRAME_SIZE=45 -DUSE_LIBUSB_PAL -DPAL_OS_HAS_EVENT_INIT -DOPTIGA_LIB_EXTERNAL="${CMAKE_CURRENT_SOURCE_DIR}/config/optiga_trust_m_config.h" -DDEBUG  -DOPTIGA_LIB_ENABLE_LOGGING)
	else()
		target_compile_definitions(${TARGET_LIBUSB_SHLIB} PRIVATE -DIFX_I2C_FRAME_SIZE=45 -DUSE_LIBUSB_PAL -DPAL_OS_HAS_EVENT_INIT -DOPTIGA_LIB_EXTERNAL="${CMAKE_CURRENT_SOURCE_DIR}/config/optiga_trust_m_config.h" -DDEBUG)
	endif()
	if(HAS_LIBUSB)
		target_link_libraries(${TARGET_LIBUSB_SHLIB} usb-1.0)
	endif(HAS_LIBUSB)
	target_link_libraries(${TARGET_LIBUSB_SHLIB} rt m crypto)

	set_target_properties( ${TARGET_LIBUSB_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()
