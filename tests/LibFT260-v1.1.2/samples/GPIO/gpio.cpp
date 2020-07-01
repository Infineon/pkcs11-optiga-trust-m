/**
* @file gpio.cpp
*
* @author FTDI
* @date 2015-07-01
*
* Copyright c 2011 Future Technology Devices International Limited
* Company Confidential
*
* The sample source code is provided as an example and is neither guaranteed
* nor supported by FTDI.
*
* Rivision History:
* 1.0 - initial version
*/

//------------------------------------------------------------------------------
#include <stdio.h>
#include <conio.h>

//------------------------------------------------------------------------------
// include FTDI libraries
//
#include "LibFT260.h"

typedef enum
{
    GPIO_0 = 0,
    GPIO_1,
    GPIO_2,
    GPIO_3,
    GPIO_4,
    GPIO_5,
    MAX_GPIO_PIN
} gpio_id;

typedef enum
{
    GPIO_A = 0,
    GPIO_B,
    GPIO_C,
    GPIO_D,
    GPIO_E,
    GPIO_F,
    GPIO_G,
    GPIO_H,
    MAX_GPIO_EXT_PIN
} gpio_ext_id;

typedef enum
{
    GPIO_IN = 0,
    GPIO_OUT
} gpio_dir;

typedef enum
{
    GPIO_INPUT_NO_CTRL = 0,
    GPIO_INPUT_PULL_UP,
    GPIO_INPUT_PULL_DOWN
} gpio_input_ctrl;

typedef enum
{
    GPIO_DS_4MA = 0,
    GPIO_DS_8MA,
    GPIO_DS_12MA,
    GPIO_DS_16MA
} gpio_driving_stregth;

typedef enum
{
    GPIO_SUSPEND_NO_CHANGE = 0,
    GPIO_SUSPEND_PULL_LOW  = 0x02,
    GPIO_SUSPEND_PULL_HIGH = 0x03
} gpio_suspend;

//------------------------------------------------------------------------------
// Global data
const int MAX_GPIO_COUNT = 14;

int GPIOArray[MAX_GPIO_COUNT] =
{
    FT260_GPIO_0, FT260_GPIO_1, FT260_GPIO_2, FT260_GPIO_3, FT260_GPIO_4, FT260_GPIO_5,
    FT260_GPIO_A, FT260_GPIO_B, FT260_GPIO_C, FT260_GPIO_D, FT260_GPIO_E, FT260_GPIO_F, FT260_GPIO_G, FT260_GPIO_H
};

char sFT260_GPIO[MAX_GPIO_COUNT][13] =
{
    "FT260_GPIO_0", "FT260_GPIO_1", "FT260_GPIO_2", "FT260_GPIO_3", "FT260_GPIO_4", "FT260_GPIO_5",
    "FT260_GPIO_A", "FT260_GPIO_B", "FT260_GPIO_C", "FT260_GPIO_D", "FT260_GPIO_E", "FT260_GPIO_F",  "FT260_GPIO_G", "FT260_GPIO_H"
};//------------------------------------------------------------------------------

void OpenAllGPIOPin(HANDLE mhandle);
void Check_Pin_config(WORD Pims);
void ReadAll(HANDLE mhandle);

//------------------------------------------------------------------------------
// main
//------------------------------------------------------------------------------

// Hardware pin connection
// FT260_GPIO_0 connect to FT260_GPIO_1
// FT260_GPIO_A connect to FT260_GPIO_B

int main(void)
{
    FT260_HANDLE mhandle = INVALID_HANDLE_VALUE;
    FT260_STATUS ftStatus = FT260_OK;
    DWORD devNum = 0;

    FT260_CreateDeviceList(&devNum);
    if (FT260_Open(0, &mhandle) != FT260_OK) {
        printf("\n open dev fail\n");
        goto EXIT;
    }

    OpenAllGPIOPin(mhandle);

    printf("\nPrepare to set GPIO G...\n");
    getchar();

    if (FT260_SelectGpioGFunction(mhandle, FT260_GPIOG_GPIO) != FT260_OK) {
        printf("\n select gpio G fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO G output\n");
    getchar();
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_G, FT260_GPIO_OUT) != FT260_OK) {
        printf("\n GPIO setdir out fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO G 0\n");
    getchar();
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_G, 0) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO G 1\n");
    getchar();
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_G, 1) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO G 0\n");
    getchar();
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_G, 0) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO G 1\n");
    getchar();
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_G, 1) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO G 0\n");
    getchar();
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_G, 0) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

    printf("\nPrepare to set GPIO G 1\n");
    getchar();
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_G, 1) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }

/*
    FT260_GPIO_SetDir(mhandle, FT260_GPIO_2, FT260_GPIO_OUT);      // FT260_GPIO_2 set out.

    printf("\nPrepare Set GPIO 2 to 0\n");
    getchar();
    FT260_GPIO_Write(mhandle, FT260_GPIO_2, 0);                    // GPIO 2 set 0
    printf("Now GPIO 2 is set to 0\n");

    printf("\nPrepare Set GPIO 2 to 1\n");
    getchar();
    FT260_GPIO_Write(mhandle, FT260_GPIO_2, 1);                    // GPIO 2 set 1
    printf("Now GPIO 2 is set to 1\n");


    printf("\nPrepare Set GPIO 2 to 0\n");
    getchar();
    FT260_GPIO_Write(mhandle, FT260_GPIO_2, 0);                    // GPIO 2 set 0
    printf("Now GPIO 2 is set to 0\n");

    printf("\nPrepare Set GPIO 2 to 1\n");
    getchar();
    FT260_GPIO_Write(mhandle, FT260_GPIO_2, 1);                    // GPIO 2 set 1
    printf("Now GPIO 2 is set to 1\n");
*/
    printf("\nPress enter to end test\n");
    getchar();

    // FT260_GPIO_Set and FT260_GPIO_Get sample
    FT260_GPIO_Report s, g;
    s.value =  FT260_GPIO_0;
    s.dir = FT260_GPIO_0 | FT260_GPIO_1 | FT260_GPIO_2 | FT260_GPIO_3 | FT260_GPIO_4 | FT260_GPIO_5;    // All pins set out.
    s.gpioN_value =  FT260_GPIO_A;
    s.gpioN_dir =  FT260_GPIO_A | FT260_GPIO_B | FT260_GPIO_C | FT260_GPIO_D | FT260_GPIO_E | FT260_GPIO_F | FT260_GPIO_G | FT260_GPIO_H;   // All pins set out.
    ftStatus = FT260_GPIO_Set(mhandle, s);
    if (ftStatus != FT260_OK) {
        printf("FT260_GPIO_Set fail : %d\n", ftStatus);
    }

    g.value = 0;
    g.dir = 0;
    g.gpioN_value = 0;
    g.gpioN_dir = 0;
    ftStatus = FT260_GPIO_Get(mhandle, &g); // It will be the same with s
    if (ftStatus != FT260_OK) {
        printf("FT260_GPIO_Get fail : %d\n", ftStatus);
    } else {
        printf("GPIO_value : %x\n", g.value);
        printf("GPIO_dir : %x\n", g.dir);
        printf("GPIO_gpioN_value : %x\n", g.gpioN_value);
        printf("GPIO_gpioN_dir : %x\n", g.gpioN_dir);
    }

    // FT260_GPIO_Set sample
    FT260_GPIO_Report r;
    r.value = FT260_GPIO_0 | FT260_GPIO_2| FT260_GPIO_3;    // FT260_GPIO_0/2/3 set high, FT260_GPIO_1/4/5 set low.
    r.dir = FT260_GPIO_0 | FT260_GPIO_3 | FT260_GPIO_5; // FT260_GPIO_0/3/5 set out, FT260_GPIO_1/2 set in.
    r.gpioN_value = FT260_GPIO_B | FT260_GPIO_C | FT260_GPIO_E | FT260_GPIO_F;  // FT260_GPIO_B/C/E/F set high, FT260_GPIO_A/D/H set low.
    r.gpioN_dir = FT260_GPIO_A | FT260_GPIO_B | FT260_GPIO_D | FT260_GPIO_H | FT260_GPIO_G; // FT260_GPIO_A/B/D/H/G set out, FT260_GPIO_B/C/E set in.
    ftStatus = FT260_GPIO_Set(mhandle, r);
    if (ftStatus != FT260_OK) {
        printf("FT260_GPIO_Set fail : %d\n", ftStatus);
    }

    ReadAll(mhandle);

    BYTE gpio0 = 0x63;    // All initial values set 99
    BYTE gpio1 = 0x63;
    BYTE gpioA = 0x63;
    BYTE gpioB = 0x63;

    // FT260_GPIO_Write, FT260_GPIO_Read and FT260_GPIO_SetDir sample

    // FT260_GPIO_0 set out
    // FT260_GPIO_1 set in
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_0, FT260_GPIO_OUT) != FT260_OK) {
        printf("\n GPIO setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_1, FT260_GPIO_IN) != FT260_OK) {
        printf("\n GPIO setdir in fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_0 : out, FT260_GPIO_1 : in\n");

    // GPIO 0 set 1
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_0, 1) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_0   set 1\n");

    if (FT260_GPIO_Read(mhandle, FT260_GPIO_0, &gpio0) != FT260_OK) {
        printf("\n GPIO read fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_Read(mhandle, FT260_GPIO_1, &gpio1) != FT260_OK) {
        printf("\n GPIO read fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_0 : %d\n", gpio0);
    printf("FT260_GPIO_1 : %d\n", gpio1);
    printf("\n");

    // GPIO set direction
    // FT260_GPIO_0 set in
    // FT260_GPIO_1 set out
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_0, FT260_GPIO_IN) != FT260_OK) {
        printf("\n GPIO setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_1, FT260_GPIO_OUT) != FT260_OK) {
        printf("\n GPIO setdir out fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_0 : in, FT260_GPIO_1 : out\n");

    // GPIO 1 set 0
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_1, 0) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_1   set 0\n");

    if (FT260_GPIO_Read(mhandle, FT260_GPIO_0, &gpio0) != FT260_OK) {
        printf("\n GPIO read fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_Read(mhandle, FT260_GPIO_1, &gpio1) != FT260_OK) {
        printf("\n GPIO read fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_0 : %d\n", gpio0);
    printf("FT260_GPIO_1 : %d\n", gpio1);
    printf("\n");

    // FT260_GPIO_A set out
    // FT260_GPIO_B set in
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_A, FT260_GPIO_OUT) != FT260_OK) {
        printf("\n GPIO setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_B, FT260_GPIO_IN) != FT260_OK) {
        printf("\n GPIO setdir in fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_A : out, FT260_GPIO_B : in\n");

    // GPIO A set 1
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_A, 1) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_A   set 1\n");

    if (FT260_GPIO_Read(mhandle, FT260_GPIO_A, &gpioA) != FT260_OK) {
        printf("\n GPIO read fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_Read(mhandle, FT260_GPIO_B, &gpioB) != FT260_OK) {
        printf("\n GPIO read fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_A : %d\n", gpioA);
    printf("FT260_GPIO_B : %d\n", gpioB);
    printf("\n");

    // FT260_GPIO_A set in
    // FT260_GPIO_B set out
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_A, FT260_GPIO_IN) != FT260_OK) {
        printf("\n GPIO setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_B, FT260_GPIO_OUT) != FT260_OK) {
        printf("\n GPIO setdir out fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_A : in, FT260_GPIO_B : out\n");

    // GPIO B set 0
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_B, 0) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_B   set 0\n");

    if (FT260_GPIO_Read(mhandle, FT260_GPIO_A, &gpioA) != FT260_OK) {
        printf("\n GPIO read fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_Read(mhandle, FT260_GPIO_B, &gpioB) != FT260_OK) {
        printf("\n GPIO read fail\n");
        goto EXIT;
    }
    printf("FT260_GPIO_A : %d\n", gpioA);
    printf("FT260_GPIO_B : %d\n", gpioB);
    printf("\n");

    // FT260_SetParam_U8 sample
    // GPIO input control
    // GPIO input pull up
    FT260_STATUS FT260STATUS = FT260_OTHER_ERROR;
    uint8 value = 0;
    gpio_input_ctrl ctrl[MAX_GPIO_PIN];
    // GPIO 0~5 pull up
    for (int idx = 0; idx < MAX_GPIO_PIN; idx++)
    {
        ctrl[idx] = GPIO_INPUT_PULL_UP;
    }

    for (int idx = 0 ; idx < MAX_GPIO_PIN; idx++)
    {
        value |=  (ctrl[idx] == GPIO_INPUT_PULL_UP) ? 0x01 << idx : 0;
    }

    FT260STATUS = FT260_SetParam_U8(mhandle, FT260_GPIO_PULL_UP, value);
    if (FT260STATUS != FT260_OK) {
        printf("GPIO input pull up fail : %d\n", FT260STATUS);
    } else {
        printf("GPIO input pull up : %d\n", FT260STATUS);
    }

    // GPIO input pull douwn
    // GPIO 0~5 pull douwn
    for (int idx = 0; idx < MAX_GPIO_PIN; idx++)
    {
        ctrl[idx] = GPIO_INPUT_PULL_DOWN;
    }

    for (int idx = 0 ; idx < MAX_GPIO_PIN; idx++)
    {
        value |=  (ctrl[idx] == GPIO_INPUT_PULL_UP) ? 0x01 << idx : 0;
    }

    FT260STATUS = FT260_SetParam_U8(mhandle, FT260_GPIO_PULL_DOWN, value);
    if (FT260STATUS != FT260_OK) {
        printf("GPIO input pull down fail : %d\n", FT260STATUS);
    } else {
        printf("GPIO input pull down : %d\n", FT260STATUS);
    }

    // GPIO open drain
    FT260STATUS = FT260_SetParam_U8(mhandle, FT260_GPIO_OPEN_DRAIN, 0x3F);
    if (FT260STATUS != FT260_OK) {
        printf("GPIO open drain fail : %d\n", FT260STATUS);
    } else {
        printf("GPIO open drain : %d\n", FT260STATUS);
    }

    // GPIO slew rate
    FT260STATUS = FT260_SetParam_U8(mhandle, FT260_GPIO_GPIO_SLEW_RATE, 0x3F);
    if (FT260STATUS != FT260_OK) {
        printf("GPIO slew rate fail : %d\n", FT260STATUS);
    } else {
        printf("GPIO slew rate : %d\n", FT260STATUS);
    }

    // FT260_SetParam_U16 sample
    // GPIO driving strength
    uint8 value1 = 0;
    uint8 value2 = 0;
    gpio_driving_stregth ds[MAX_GPIO_PIN];
    gpio_driving_stregth idy = GPIO_DS_4MA;

    for (int idx = 0; idx < MAX_GPIO_PIN; idx++)
    {
        ds[idx] = idy;
    }

    for (int idx = 0; idx < 4; idx++)
    {
        value1 |= ds[idx] << (idx*2);
    }

    for (int idx = 4; idx < 6; idx++)
    {
        value2 |= ds[idx-4] << ((idx-4)*2);
    }

    uint16 data = (value1 << 8) | value2;   // Value 1 for high byte, value 2 for low byte.

    FT260STATUS = FT260_SetParam_U16(mhandle, FT260_GPIO_DRIVE_STRENGTH, data);
    if (FT260STATUS != FT260_OK) {
        printf("GPIO driving strength fail : %d\n", FT260STATUS);
    } else {
        printf("GPIO driving strength : %d\n", FT260STATUS);
    }

    // GPIO suspend
    // Set gpio 0~3 pull high when suspend out happened
    // Set gpio 4~5 pull low when suspend out happened
    value1 = 0;
    value2 = 0;
    gpio_suspend gpio[MAX_GPIO_PIN];

    for (int idx = 0; idx < 4; idx++)
    {
        gpio[idx] = GPIO_SUSPEND_PULL_HIGH;
    }

    for (int idx = 4; idx < 6; idx++)
    {
        gpio[idx] = GPIO_SUSPEND_PULL_LOW;
    }

    for (int idx = 0; idx < 4; idx++)
    {
        value1 |= gpio[idx] << (idx*2);
    }

    for (int idx = 0; idx < 2; idx++)
    {
        value2 |= gpio[idx+4] << (idx*2);
    }

    data = (value1 << 8) | value2;  // Value 1 for high byte, value 2 for low byte.

    FT260STATUS = FT260_SetParam_U16(mhandle, FT260_GPIO_GROUP_SUSPEND_0, data);
    if (FT260STATUS != FT260_OK) {
        printf("GPIO suspend 0 fail : %d\n", FT260STATUS);
    } else {
        printf("GPIO suspend 0 : %d\n", FT260STATUS);
    }

    // GPIO NSuspend
    value1 = 0;
    value2 = 0;
    gpio_suspend gpioEx[MAX_GPIO_EXT_PIN];

    for (int idx = 0; idx < 4; idx++)
    {
        gpioEx[idx] = GPIO_SUSPEND_PULL_HIGH;
    }

    for (int idx = 4; idx < 6; idx++)
    {
        gpioEx[idx] = GPIO_SUSPEND_PULL_LOW;
    }

    for (int idx = 0; idx < 4; idx++)
    {
        value1 |= gpioEx[idx] << (idx*2);
    }

    for (int idx = 0; idx < 2; idx++)
    {
        value2 |= gpioEx[idx+4] << (idx*2);
    }

    data = (value1 << 8) | value2;  // Value 1 for high byte, value 2 for low byte.

    FT260STATUS = FT260_SetParam_U16(mhandle, FT260_GPIO_GROUP_SUSPEND_A, data);
    if (FT260STATUS != FT260_OK) {
        printf("GPIO suspend A fail : %d\n", FT260STATUS);
    } else {
        printf("GPIO suspend A : %d\n", FT260STATUS);
    }

    system("PAUSE");
EXIT:
    FT260_Close(mhandle);

    return 0;
}

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

void OpenAllGPIOPin(HANDLE mhandle)
{
    // enable gpio 0 ~ 1
    OpenGPIOPins(mhandle, OPEN_GPIO0_GPIO1);
    // enable gpio 2
    OpenGPIOPins(mhandle, OPEN_GPIO2_TO_GPIO);
    // enable gpio 3
    OpenGPIOPins(mhandle, OPEN_GPIO3);
    // enable gpio 4 ~ 5
    OpenGPIOPins(mhandle, OPEN_GPIO4_GPIO5);
    // enable gpio A
    OpenGPIOPins(mhandle, OPEN_GPIOA_TO_GPIO);
    // enable gpio B , C , D , E , F, H
    OpenGPIOPins(mhandle, OPEN_GPIOB_C_D_E_F_H);
    // enable gpio G
    OpenGPIOPins(mhandle, OPEN_GPIOG_TO_GPIO);
}

void ReadAll(HANDLE mhandle)
{
    printf("\nRead all\n");
    BYTE b = 0xFF;
    for (int i = 0; i < MAX_GPIO_COUNT; i++)
    {
        FT260_GPIO_Read(mhandle, GPIOArray[i], &b);
        printf("%s = %d\n", sFT260_GPIO[i], b);
    }
    printf("\n");
}