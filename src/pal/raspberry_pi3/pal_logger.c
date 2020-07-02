/**
INFINEON_OPTIGA_SOURCE_CODE_BOILER_PLATE
*
* \file    pal_logger.c
*
* \brief   This file provides the prototypes declarations for pal logger.
*
* \ingroup grPAL
*
* @{
*/

#include "optiga/pal/pal_logger.h"
/// @cond hidden
//lint --e{552} suppress "Accessed by user of this structure"
pal_logger_t logger_console =
{
        .logger_config_ptr = NULL,
        .logger_rx_flag = 1,
        .logger_tx_flag = 1
};
//lint --e{552} suppress "Accessed by user of this structure"
pal_logger_t cunit_console =
{
        .logger_config_ptr = NULL,
        .logger_rx_flag = 1,
        .logger_tx_flag = 1
};

pal_status_t pal_logger_init(void * p_logger_context)
{
    return PAL_STATUS_SUCCESS;
}


pal_status_t pal_logger_deinit(void * p_logger_context)
{
    return PAL_STATUS_SUCCESS;
}

/**
 * Write Data via pal logger
 *
 */
pal_status_t pal_logger_write(void * p_logger_context, const uint8_t * p_log_data, uint32_t log_data_length)
{

    int32_t return_status = PAL_STATUS_SUCCESS;
	printf("%s",p_log_data);
    return ((pal_status_t)return_status);
   
}

/**
 * Read Data via pal logger
 *
 */
pal_status_t pal_logger_read(void * p_logger_context, uint8_t * p_log_data, uint32_t log_data_length)
{

    int32_t return_status = PAL_STATUS_SUCCESS;
    return ((pal_status_t)return_status);

}
/**
* @}
*/
