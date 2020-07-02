/**
INFINEON_OPTIGA_SOURCE_CODE_BOILER_PLATE
*
* \file pal_ifx_i2c_config.h
*
* \brief   This file provides the platform abstraction layer extern declarations for IFX I2C.
*
* \ingroup  grPAL
*
* @{
*/

#ifndef _PAL_IFX_I2C_CONFIG_H_
#define _PAL_IFX_I2C_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "pal.h"
#include "pal_i2c.h"
#include "pal_gpio.h"
#include "pal_os_datastore.h"

extern pal_i2c_t optiga_pal_i2c_context_0;
extern pal_gpio_t optiga_vdd_0;
extern pal_gpio_t optiga_reset_0;

#ifdef __cplusplus
}
#endif

#endif /* _PAL_IFX_I2C_CONFIG_H_ */

/**
* @}
*/
