/**
* @file gpio_od.cpp
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

typedef enum{
    GPO_LOW,
    GPO_HIGH,
} gpo_status;

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
void ReadAll(HANDLE mhandle);

//------------------------------------------------------------------------------
// main
//------------------------------------------------------------------------------
int main(void)
{
    FT260_HANDLE mhandle = INVALID_HANDLE_VALUE;
    DWORD devNum = 0;
    BYTE  od_config = 0;

    FT260_CreateDeviceList(&devNum);
    if (FT260_Open(0, &mhandle) != FT260_OK) {
		printf("\n open dev fail\n");
		goto EXIT;
    }

    printf("sconfig pins to GPIO 0~5 \n");

    OpenAllGPIOPin(mhandle);

    FT260_GPIO_Reset_OD(mhandle);

    od_config |= FT260_GPIO_0;
    od_config |= FT260_GPIO_1;
    od_config |= FT260_GPIO_2;
    od_config |= FT260_GPIO_3;
    od_config |= FT260_GPIO_4;
    od_config |= FT260_GPIO_5;

    printf("open drain 0x%x\n", od_config);
    FT260_GPIO_Set_OD(mhandle, od_config);

    printf("set pins driection\n");
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_0, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO0 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_1, GPIO_OUT) != FT260_OK) {
        printf("\n GPI1 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_2, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO2 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_3, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO3 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_4, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO4 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_5, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO5 setdir out fail\n");
        goto EXIT;
    }

    printf("----------------GPIO TEST for open drain enable-----------------\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_0, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_0 Target High, the open drain must be tri-satet\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_0, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_0 Target Low, the open drain must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_1, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_1 Target High, the open drain must be tri-satet\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_1, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_1 Target Low, the open drain must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_2, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_2 Target High, the open drain must be tri-satet\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_2, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_2 Target Low, the open drain must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_3, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_3 Target High, the open drain must be tri-satet\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_3, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_3 Target Low, the open drain must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_4, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_4 Target High, the open drain must be tri-satet\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_4, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_4 Target Low, the open drain must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_5, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_5 Target High, the open drain must be tri-satet\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_5, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_5 Target Low, the open drain must be low\n");

    system("pause");

    printf("----------------GPO TEST for open drain disable at GPIO 1~3~4 / -----------------\n");

    FT260_GPIO_Reset_OD(mhandle);

    od_config =0;

    od_config |= FT260_GPIO_0;
    od_config |= FT260_GPIO_2;
    od_config |= FT260_GPIO_5;

    printf("open drain 0x%x\n", od_config);
    FT260_GPIO_Set_OD(mhandle, od_config);

    printf("set pins direction\n");
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_0, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO0 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_1, GPIO_OUT) != FT260_OK) {
        printf("\n GPI1 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_2, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO2 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_3, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO3 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_4, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO4 setdir out fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_5, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO5 setdir out fail\n");
        goto EXIT;
    }

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_0, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_0 check it must be high\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_0, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_0 check it must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_1, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_1 check it must be high\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_1, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_1 check it must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_2, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_2 check it must be high\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_2, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_2 check it must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_3, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_3 check it must be high\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_3, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_3 check it must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_4, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_4 check it must be high\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_4, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_4 check it must be low\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_5, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_5 check it must be high\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_5, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_5 check it must be low\n");
    system("pause");

    printf("----------------GPIO TEST for open drain enable-----------------\n");

    FT260_GPIO_Reset_OD(mhandle);

    od_config = 0;
    od_config |= FT260_GPIO_0;
    od_config |= FT260_GPIO_1;
    od_config |= FT260_GPIO_2;
    od_config |= FT260_GPIO_3;
    od_config |= FT260_GPIO_4;
    od_config |= FT260_GPIO_5;

    printf("open drain 0x%x\n", od_config);
    FT260_GPIO_Set_OD(mhandle, od_config);

    printf("set pins driection\n");
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_0, GPIO_IN) != FT260_OK) {
        printf("\n GPIO0 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_1, GPIO_IN) != FT260_OK) {
        printf("\n GPI1 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_2, GPIO_IN) != FT260_OK) {
        printf("\n GPIO2 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_3, GPIO_IN) != FT260_OK) {
        printf("\n GPIO3 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_4, GPIO_IN) != FT260_OK) {
        printf("\n GPIO4 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_5, GPIO_IN) != FT260_OK) {
        printf("\n GPIO5 setdir in fail\n");
        goto EXIT;
    }

    system("pause");
    BYTE GPI = 0xff;
    printf("Please target FT260_GPI_0 high\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_0, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_0 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_0 low\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_0, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_0 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_1 high\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_1, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_1 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_1 low\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_1, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_1 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_2 high\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_2, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_2 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_2 low\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_2, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_2 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_3 high\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_3, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_3 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_3 low\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_3, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_3 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_4 high\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_4, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_4 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_4 low\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_4, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_4 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_5 high\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_5, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_5 is %d\n", GPI);

    system("pause");
    GPI = 0xff;
    printf("Please target FT260_GPI_5 low\n");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_5, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_5 is %d\n", GPI);

    system("pause");

    printf("----------------GPI TEST all-----------------\n");

    FT260_GPIO_Reset_OD(mhandle);

    od_config =0;
    od_config |= FT260_GPIO_2;
    od_config |= FT260_GPIO_4;
    od_config |= FT260_GPIO_5;

    printf("open drain 0x%x\n", od_config);
    FT260_GPIO_Set_OD(mhandle, od_config);

    printf("set pins driection\n");
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_0, GPIO_OUT) != FT260_OK) {
        printf("\n GPIO0 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_1, GPIO_IN) != FT260_OK) {
        printf("\n GPI1 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_2, GPIO_OUT) != FT260_OK) {   // open drain
        printf("\n GPIO2 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_3, GPIO_IN) != FT260_OK) {
        printf("\n GPIO3 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_4, GPIO_OUT) != FT260_OK) {   // open drain
        printf("\n GPIO4 setdir in fail\n");
        goto EXIT;
    }
    if (FT260_GPIO_SetDir(mhandle, FT260_GPIO_5, GPIO_IN) != FT260_OK) {   // open drain
        printf("\n GPIO5 setdir in fail\n");
        goto EXIT;
    }

    // gpio 0
    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_0, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_0 check it must be high\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_0, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_0 check it must be low\n");

    system("pause");

    // gpio 1
    GPI = 0xff;
    printf("Please target FT260_GPI_1 high\n");
    system("pause");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_1, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_1 is %d\n", GPI);

    system("pause");
    printf("Please target FT260_GPI_1 low\n");
    system("pause");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_1, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_1 is %d\n", GPI);

    system("pause");

    // gpio 2
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_2, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_2 Target High, the open drain must be tri-satet\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_2, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_2 Target Low, the open drain must be low\n");

    system("pause");

    // gpio 3
    GPI = 0xff;
    printf("Please target FT260_GPI_3 high\n");
    system("pause");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_3, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_3 is %d\n", GPI);

    system("pause");
    printf("Please target FT260_GPI_3 low\n");
    system("pause");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_3, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_3 is %d\n", GPI);

    system("pause");

    // gpio 4
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_4, GPO_HIGH) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_4 Target High, the open drain must be tri-satet\n");

    system("pause");
    if (FT260_GPIO_Write(mhandle, FT260_GPIO_4, GPO_LOW) != FT260_OK) {
        printf("\n GPIO write fail\n");
        goto EXIT;
    }
    printf("FT260_GPO_4 Target Low, the open drain must be low\n");

    system("pause");

    // gpio 5
    GPI = 0xff;
    printf("Please target FT260_GPI_5 high\n");
    system("pause");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_5, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_5 is %d\n", GPI);

    system("pause");
    printf("Please target FT260_GPI_5 low\n");
    system("pause");
    if (FT260_OK != FT260_GPIO_Read(mhandle, FT260_GPIO_5, &GPI))
    {
        printf("read error\n");
    }
    printf("Read data FT260_GPI_5 is %d\n", GPI);

    FT260_GPIO_Reset_OD(mhandle);
EXIT:
    FT260_Close(mhandle);
    return 0;
}

void OpenAllGPIOPin(HANDLE mhandle)
{
    // enable gpio 0 ~ 1
    FT260_EnableI2CPin(mhandle, false);
    // enable gpio 2
    FT260_SelectGpio2Function(mhandle, FT260_GPIO2_GPIO);
    // enable gpio 3
    FT260_SetWakeupInterrupt(mhandle, false);
    // enable gpio 4 ~ 5
    FT260_EnableDcdRiPin(mhandle, false);
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
