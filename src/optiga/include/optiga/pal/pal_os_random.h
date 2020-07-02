/**
INFINEON_OPTIGA_SOURCE_CODE_BOILER_PLATE
*
* \file pal_os_random.h
*
* \brief   This file provides the prototype declarations of PAL OS random functionalities
*
* \ingroup  grPAL
*
* @{
*/

#ifndef _PAL_OS_RANDOM_H_
#define _PAL_OS_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************************************************************
 * HEADER FILES
 *********************************************************************************************************************/
#include "pal.h"

/**********************************************************************************************************************
 * MACROS
 *********************************************************************************************************************/


/**********************************************************************************************************************
 * ENUMS
 *********************************************************************************************************************/


/**********************************************************************************************************************
 * DATA STRUCTURES
 *********************************************************************************************************************/


/**********************************************************************************************************************
 * API Prototypes
 *********************************************************************************************************************/

/**
 * \brief Gets the random counter value.
 *
 * \details
 * Gets the random counter value.
 *
 * \pre
 * None
 *
 * \note
 * None
 *
 *
 * \retval uint32_t   random counter value.
 */
uint32_t pal_os_random_get_counter(void);

#ifdef __cplusplus
}
#endif

#endif /* _PAL_OS_RANDOM_H_ */

/**
* @}
*/
