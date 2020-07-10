/**
* @file getting_started.cpp
*
* @author FTDI
* @date 2015-07-08
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
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>

//------------------------------------------------------------------------------
// include FTDI libraries
//
#include "LibFT260.h"

#define MASK_1 0x0f

void ListAllDevicePaths()
{
    DWORD devNum = 0;
    WCHAR pathBuf[128];

    FT260_CreateDeviceList(&devNum);

    for(DWORD i = 0; i < devNum; i++)
    {
        FT260_GetDevicePath(pathBuf, 128, i);
        wprintf(L"Index:%d\nPath:%s\n\n", i, pathBuf);
    }
}

//------------------------------------------------------------------------------
// main
//------------------------------------------------------------------------------
int main(void)
{
    FT260_STATUS ftStatus = FT260_OTHER_ERROR;
    FT260_HANDLE ft260Handle = INVALID_HANDLE_VALUE;
    DWORD devNum = 0;

    // Show all HID device path
    ListAllDevicePaths();

    FT260_CreateDeviceList(&devNum);
    if (devNum < 1)
    {
        return 0;
    }

    // Open device by index
    ftStatus = FT260_Open(0, &ft260Handle);
    if (FT260_OK != ftStatus)
    {
        printf("Open device Failed, status: %d\n", ftStatus);
        return 0;
    }
    else
    {
        printf("Open device OK\n");
    }

    // Show version information
    DWORD dwChipVersion = 0;

    ftStatus = FT260_GetChipVersion(ft260Handle, &dwChipVersion);
    if (FT260_OK != ftStatus)
    {
        printf("Get chip version Failed, status: %d\n", ftStatus);
    }
    else
    {
        printf("Get chip version OK\n");
        printf("Chip version : %d.%d.%d.%d\n",
            ((dwChipVersion >> 24) & MASK_1),
            ((dwChipVersion >> 16) & MASK_1),
            ((dwChipVersion >> 8) & MASK_1),
            (dwChipVersion & MASK_1) );
    }

    //    Initailize as an I2C master, and read/write data to an I2C slave
    //    FT260_I2CMaster_Init
    //    FT260_I2CMaster_Read
    //    FT260_I2CMaster_Write

    system("PAUSE");

    // Close device
    FT260_Close(ft260Handle);
    return 0;
}