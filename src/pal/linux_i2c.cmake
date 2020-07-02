if(UNIX)
	set(TARGET_I2C_SHLIB ${PROJECT_NAME}-i2c-linux-pkcs11)

	set(TRUSTM_I2C_SRCS 
		${TRUSTM_PATH}/pal/raspberry_pi3/pal.c
		${TRUSTM_PATH}/pal/raspberry_pi3/pal_gpio.c
		${TRUSTM_PATH}/pal/raspberry_pi3/pal_i2c.c
		${TRUSTM_PATH}/pal/raspberry_pi3/pal_ifx_i2c_config.c
		${TRUSTM_PATH}/pal/raspberry_pi3/pal_os_event.c
		${TRUSTM_PATH}/pal/raspberry_pi3/pal_os_datastore.c
		${TRUSTM_PATH}/pal/raspberry_pi3/pal_logger.c
		${TRUSTM_PATH}/pal/raspberry_pi3/pal_os_lock.c
		${TRUSTM_PATH}/pal/raspberry_pi3/pal_os_timer.c
                ${TRUSTM_PATH}/pal/raspberry_pi3/pal_os_memory.c  
                ${TRUSTM_PATH}/pal/pal_crypt_openssl.c
	)
	set(TRUSTM_I2C_INC ${TRUSTM_PATH}/pal/raspberry_pi3)
	add_library(${TARGET_I2C_SHLIB} SHARED ${TRUSTM_CORE_SRCS} ${TRUSTM_I2C_SRCS})
	target_include_directories(${TARGET_I2C_SHLIB}  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} 
				   ${TRUSTM_PATH}/optiga/include
				   ${TRUSTM_I2C_INC}
				   ${TRUSTM_PATH}/externals/pkcs11/)
	target_compile_definitions(${TARGET_I2C_SHLIB} PRIVATE  -DOPTIGA_USE_SOFT_RESET -DPAL_OS_HAS_EVENT_INIT)
	target_link_libraries(${TARGET_I2C_SHLIB} rt)
	set_target_properties( ${TARGET_I2C_SHLIB}
		PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../lib"
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/../bin"
	)

else()
	message(FATAL_ERROR, "You are trying to run linux cmake file on a different OS")	
endif()
