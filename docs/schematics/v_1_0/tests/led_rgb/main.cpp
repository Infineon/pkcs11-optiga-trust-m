#include <windows.h>

#include <stdio.h>
#include <conio.h>

#include "LibFT260.h"

typedef enum{
     OPEN_GPIO0_GPIO1,
     CLOSE_GPIO0_GPIO1,
     OPEN_GPIO3,
     CLOSE_GPIO3,
     OPEN_GPIO4_GPIO5,
     CLOSE_GPIO4_GPIO5,
     OPEN_GPIOB_C_D_E_F_H,
     CLOSE_GPIOB_C_D_E_F_H,
     OPEN_GPIO2_TO_GPIO,
     OPEN_GPIOG_TO_GPIO,
     OPEN_GPIOA_TO_GPIO,
} GPIO_FUNCTION;

void OpenGPIOPins(HANDLE mhandle, GPIO_FUNCTION idx)
{
    switch(idx)
    {
        case OPEN_GPIO0_GPIO1:
            FT260_EnableI2CPin(mhandle, false);
        break;
        case CLOSE_GPIO0_GPIO1:
            FT260_EnableI2CPin(mhandle, true);
        break;
        case OPEN_GPIO3:
            FT260_SetWakeupInterrupt(mhandle, false);
        break;
        case CLOSE_GPIO3:
            FT260_SetWakeupInterrupt(mhandle, true);
        break;
        case OPEN_GPIO4_GPIO5:
            FT260_EnableDcdRiPin(mhandle, false);
        break;
        case CLOSE_GPIO4_GPIO5:
            FT260_EnableDcdRiPin(mhandle, true);
        break;
        case OPEN_GPIOB_C_D_E_F_H:
            FT260_SetUartToGPIOPin(mhandle);
        break;
        case CLOSE_GPIOB_C_D_E_F_H:
            FT260_SetGPIOToUartPin(mhandle);
        break;
        case OPEN_GPIO2_TO_GPIO:
            FT260_SelectGpio2Function(mhandle, FT260_GPIO2_GPIO);
        break;
        case OPEN_GPIOG_TO_GPIO:
            FT260_SelectGpioGFunction(mhandle, FT260_GPIOG_GPIO);
        break;
        case OPEN_GPIOA_TO_GPIO:
            FT260_SelectGpioAFunction(mhandle, FT260_GPIOA_GPIO);
        break;
    }
}

int main(void)
{
    // value of GPIOs to test
    BYTE GPIO_C = 1;
    BYTE GPIO_B = 1;
    BYTE GPIO_E = 1;

    FT260_HANDLE mhandle = INVALID_HANDLE_VALUE;
    FT260_STATUS ftStatus = FT260_OK;
    DWORD devNum = 0;
    
    // open device
    FT260_CreateDeviceList(&devNum);
    if (FT260_Open(0, &mhandle) != FT260_OK) {
        printf("\n open dev fail\n");
        getchar();
        goto EXIT;
    }

    // enable gpio B , C , D , E , F, H
    OpenGPIOPins(mhandle, OPEN_GPIOB_C_D_E_F_H);
    
    printf("\nPrepare to set GPIO B, C and E...\n");

    // set direction  GPIOE
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_E, FT260_GPIO_OUT) != FT260_OK){
        printf("\n GPIO E setdir out fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO E to %i\n",GPIO_E);

    // set GPIO E
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_E, GPIO_E) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

    // set direction  GPIOB
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_B, FT260_GPIO_OUT) != FT260_OK){
        printf("\n GPIO B setdir out fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO B to %i\n",GPIO_B);

    // set GPIO B
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_B, GPIO_B) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

    // set direction  GPIOC
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_C, FT260_GPIO_OUT) != FT260_OK){
        printf("\n GPIO C setdir out fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO C to %i\n",GPIO_E);

    // set GPIO C
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_C, GPIO_C) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

EXIT:
    FT260_Close(mhandle);

    return 0;
}


