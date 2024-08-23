//------------------------------------------------------------------------------
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>

//------------------------------------------------------------------------------
// include FTDI libraries
//
#include "LibFT260.h"

#define BIT0 0x01
#define BIT1 0x02

#define MODE_2 0

//------------------------------------------------------------------------------
// main
//------------------------------------------------------------------------------
int main(void)
{
    FT260_STATUS ftStatus = FT260_OTHER_ERROR;
    FT260_HANDLE handle = INVALID_HANDLE_VALUE;
    UartConfig uartConfig;
    DWORD devNum = 0;

    byte buffer[10] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
    byte buffer2[50] = {0};

    DWORD dwRealAccessData = 0;
    DWORD dwAvailableData = 0;

    FT260_CreateDeviceList(&devNum);
    printf("Device Number : %d\n", devNum);

#if MODE_2
    // Run this sample with chip mode 2
    ftStatus = FT260_Open(0, &handle);
#else
    // Run this sample with chip mode 0 or chip mode 3
    ftStatus = FT260_Open(1, &handle);
#endif

    if (FT260_OK != ftStatus)
    {
        printf("Open NG, status : %d\n", ftStatus);
    }

    ftStatus = FT260_UART_Init(handle);

    if (FT260_OK != ftStatus)
    {
        printf("UART Init NG, status : %d\n", ftStatus);
    }

    //config TX_ACTIVE for UART 485
    FT260_SelectGpioAFunction(handle, FT260_GPIOA_TX_ACTIVE);

    //config UART
    if (FT260_UART_SetFlowControl(handle, FT260_UART_XON_XOFF_MODE) != FT260_OK) {
        printf("UART Set flow ctrl NG : %d\n", ftStatus);
    }
    ULONG ulBaudrate = 115200;
    if (FT260_UART_SetBaudRate(handle, ulBaudrate) != FT260_OK) {
        printf("UART Set baud NG : %d\n", ftStatus);
    }
    if (FT260_UART_SetDataCharacteristics(handle, FT260_DATA_BIT_8, FT260_STOP_BITS_1, FT260_PARITY_NONE) != FT260_OK) {
        printf("UART Set characteristics NG : %d\n", ftStatus);
    }
    if (FT260_UART_SetBreakOff(handle) != FT260_OK) {
        printf("UART Set break NG : %d\n", ftStatus);
    }

    ftStatus = FT260_UART_GetConfig(handle, &uartConfig);
    if (FT260_OK != ftStatus)
    {
        printf("UART Get config NG : %d\n", ftStatus);
    }
    else
    {
        printf("config baud:%ld, ctrl:%d, data_bit:%d, stop_bit:%d, parity:%d, breaking:%d\n",
            uartConfig.baud_rate, uartConfig.flow_ctrl, uartConfig.data_bit, uartConfig.stop_bit, uartConfig.parity, uartConfig.breaking);
    }

    // Write data
    ftStatus = FT260_UART_Write(handle, buffer, 10, 5, &dwRealAccessData);
    if (FT260_OK != ftStatus)
    {
        printf("UART Write NG : %d\n", ftStatus);
    }
    else
    {
        printf("Write bytes : %d\n", dwRealAccessData);
    }

    printf("Prepare to read data. Press Enter to continue.\n");
    getchar();

    // Read data
    if (FT260_UART_GetQueueStatus(handle, &dwAvailableData) != FT260_OK) {
        printf("UART Read status NG\n");
    } else {
        printf("dwAvailableData : %d\n", dwAvailableData);
    }

    ftStatus = FT260_UART_Read(handle, buffer2, 50, dwAvailableData, &dwRealAccessData);
    if (FT260_OK != ftStatus)
    {
        printf("UART Read NG : %d\n", ftStatus);
    }
    else
    {
        printf("Read bytes : %d\n", dwRealAccessData);
        printf("buffer : %s\n", buffer2);
    }

    // Get UART DCD RI status
    byte value = 0x00;
    FT260_EnableDcdRiPin(handle, true);
    FT260_UART_GetDcdRiStatus(handle, &value);
    printf("\nStatus DCD:%d, RI:%d\n", (value&BIT0)?1:0, (value&BIT1)?1:0);

    // Set UART RI Wakeup - Rising edge
    FT260_EnableDcdRiPin(handle, true);
    FT260_UART_EnableRiWakeup(handle, true);
    FT260_SetWakeupInterrupt(handle, false);
    FT260_UART_SetRiWakeupConfig(handle, FT260_RI_WAKEUP_RISING_EDGE);

    printf("\nMake PC enter suspend, and then make RI Pin rise.\n");
    getchar();

    system("PAUSE");

    FT260_Close(handle);

    return 0;
}