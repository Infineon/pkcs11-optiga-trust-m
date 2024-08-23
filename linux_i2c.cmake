# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT

if(UNIX)
	set(TARGET_I2C_SHLIB ${PROJECT_NAME}-i2c-linux-pkcs11)

	set(TRUSTM_I2C_SRCS 
		${TRUSTM_PATH}/extras/pal/linux/pal.c
		${TRUSTM_PATH}/extras/pal/linux/pal_gpio_gpiod.c
		${TRUSTM_PATH}/extras/pal/linux/pal_i2c.c
		${TRUSTM_PATH}/extras/pal/linux/target/gpiod/pal_ifx_i2c_config.c
		${TRUSTM_PATH}/extras/pal/linux/pal_os_event.c
		${TRUSTM_PATH}/extras/pal/linux/pal_os_datastore.c
		${TRUSTM_PATH}/extras/pal/linux/pal_logger.c
		${TRUSTM_PATH}/extras/pal/linux/pal_os_lock.c
		${TRUSTM_PATH}/extras/pal/linux/pal_os_timer.c
        ${TRUSTM_PATH}/extras/pal/linux/pal_os_memory.c
        ${TRUSTM_PATH}/extras/pal/linux/pal_shared_mutex.c  
        ${TRUSTM_PATH}/extras/pal/pal_crypt_openssl.c
	)
	set(TRUSTM_I2C_INC ${TRUSTM_PATH}/extras/pal/linux/include)
	add_library(${TARGET_I2C_SHLIB} SHARED ${TRUSTM_CORE_SRCS} ${TRUSTM_I2C_SRCS})
	target_include_directories(${TARGET_I2C_SHLIB} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${TRUSTM_I2C_INC})
	if(ENABLE_DEBUG)
		message("-----> I2C DEBUG mode")
		target_compile_definitions(${TARGET_I2C_SHLIB} PRIVATE  -DPAL_OS_HAS_EVENT_INIT -DOPTIGA_LIB_EXTERNAL="${CMAKE_CURRENT_SOURCE_DIR}/config/optiga_trust_m_config.h" -DDEBUG -DOPTIGA_LIB_ENABLE_LOGGING -DHAS_LIBGPIOD)
	else()
		target_compile_definitions(${TARGET_I2C_SHLIB} PRIVATE  -DPAL_OS_HAS_EVENT_INIT -DOPTIGA_LIB_EXTERNAL="${CMAKE_CURRENT_SOURCE_DIR}/config/optiga_trust_m_config.h" -DHAS_LIBGPIOD)
	endif()
	
	target_link_libraries(${TARGET_I2C_SHLIB} rt crypto pthread gpiod)
	set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")
	set_target_properties( ${TARGET_I2C_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()
