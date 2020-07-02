/**
INFINEON_OPTIGA_SOURCE_CODE_BOILER_PLATE
*
* \file    pal_logger.h
*
* \brief   This file provides the prototypes declarations for pal logger.
*
* \ingroup grPAL
*
* @{
*/


#ifndef _PAL_LOGGER_H_
#define _PAL_LOGGER_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <DAVE.h>
#include "optiga/pal/pal.h"

typedef struct pal_logger
{
  /// Pointer to logger hardware
  void * logger_config_ptr;
  /// Receive complete flag
  volatile uint8_t logger_rx_flag;
  /// Transmit complete flag
  volatile uint8_t logger_tx_flag;

} pal_logger_t;

/**
 * \brief Writes to logger port.
 *
 * \details
 * Writes to logger port.
 * - Invokes the platform dependent function to log the information provided.<br>
 *
 * \pre
 * - The pal_logger is initialized if required.
 *
 * \note
 * - None
 *
 * \param[in] p_logger_context    Valid pointer to the PAL logger context that should be initialized
 * \param[in] p_log_data          Pointer to the log data (data to be logged)
 * \param[in] log_data_length     Length of data to be logged.
 *
 * \retval    PAL_STATUS_SUCCESS  In case of successfully written to logger
 * \retval    PAL_STATUS_FAILURE  In case of failure while writing to logger
 *
 */
pal_status_t pal_logger_write(void * p_logger_context, const uint8_t * p_log_data, uint32_t log_data_length);

/**
 * \brief Read to logger port.
 *
 * \details
 * Reads to logger port.
 * - Invokes the platform dependent function to log the information provided.<br>
 *
 * \pre
 * - The pal_logger is initialized if required.
 *
 * \note
 * - None
 *
 * \param[in] p_logger_context    Valid pointer to the PAL logger context that should be initialized
 * \param[in] p_log_data          Pointer to the log data (data to be logged)
 * \param[in] log_data_length     Length of data to be logged.
 *
 * \retval    PAL_STATUS_SUCCESS  In case of successfully read to logger
 * \retval    PAL_STATUS_FAILURE  In case of failure while read to logger
 *
 */
pal_status_t pal_logger_read(void * p_logger_context, uint8_t * p_log_data, uint32_t log_data_length);

#ifdef __cplusplus
}
#endif

#endif /*_PAL_LOGGER_H_ */

/**
* @}
*/
