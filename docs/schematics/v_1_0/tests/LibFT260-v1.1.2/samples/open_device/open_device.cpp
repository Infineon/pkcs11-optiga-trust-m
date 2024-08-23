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

WORD FT260_Vid = 0x0403;
WORD FT260_Pid = 0x6030;

std::string sFT260Status[18] =
{
    "FT260_OK",
    "FT260_INVALID_HANDLE",
    "FT260_DEVICE_NOT_FOUND",
    "FT260_DEVICE_NOT_OPENED",
    "FT260_DEVICE_OPEN_FAIL",
    "FT260_DEVICE_CLOSE_FAIL",
    "FT260_INCORRECT_INTERFACE",
    "FT260_INCORRECT_CHIP_MODE",
    "FT260_DEVICE_MANAGER_ERROR",
    "FT260_IO_ERROR",
    "FT260_INVALID_PARAMETER",
    "FT260_NULL_BUFFER_POINTER",
    "FT260_BUFFER_SIZE_ERROR",
    "FT260_UART_SET_FAIL",
    "FT260_RX_NO_DATA",
    "FT260_GPIO_WRONG_DIRECTION",
    "FT260_INVALID_DEVICE",
    "FT260_OTHER_ERROR"
};

bool IsFT260Dev(WCHAR* devPath);
const char* FT260StatusToString(FT260_STATUS i);

//------------------------------------------------------------------------------
// main
//------------------------------------------------------------------------------
int main(void)
{
    FT260_STATUS ftStatus = FT260_OTHER_ERROR;
    FT260_HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD devNum = 0;
    WCHAR pathBuf[128];

    FT260_CreateDeviceList(&devNum);
    printf("Number of devices : %d\n\n", devNum);

    for(DWORD i = 0; i < devNum; i++)
    {
        // Open device by index
        ftStatus = FT260_Open(i, &handle);
        if (FT260_OK != ftStatus)
        {
            printf("Open device index:%d NG, status: %s\n", i, FT260StatusToString(ftStatus));
        }
        else
        {
            printf("Open device index:%d OK\n", i);
            FT260_Close(handle);
        }

        // Get device path and open device by device path
        ftStatus = FT260_GetDevicePath(pathBuf, 128, i);
        if (FT260_OK != ftStatus)
        {
            printf("Get Device Path NG, status: %s\n", FT260StatusToString(ftStatus));
        }
        else
        {
            wprintf(L"Device path:%s \n", pathBuf);
        }

        ftStatus = FT260_OpenByDevicePath(pathBuf, &handle);
        if (FT260_OK != ftStatus)
        {
            printf("Open NG, status: %s\n", FT260StatusToString(ftStatus));
            if(false == IsFT260Dev(pathBuf))
            {
                printf("Not FT260 device\n");
            }
        }
        else
        {
            printf("Open OK\n");
            FT260_Close(handle);
        }
        printf("\n");
    }

    // Open device by Vid/Pid
    ftStatus = FT260_OpenByVidPid(FT260_Vid, FT260_Pid, 0, &handle);

    if (FT260_OK != ftStatus)
    {
        printf("Open device by vid pid NG, status: %s\n", FT260StatusToString(ftStatus));
    }
    else
    {
        printf("Open device by vid pid OK\n");
        FT260_Close(handle);
    }
    printf("\n");

    // Open device by "FT260 Vid/Pid/Interface 0" string
    WCHAR *sOpenDeviceName = L"vid_0403&pid_6030&mi_00";
    WCHAR sDevicePath[256];
    DWORD iDeveiceCount = 0;
    FT260_CreateDeviceList(&iDeveiceCount);

    for(DWORD i = 0; i < iDeveiceCount; i++)
    {
        ftStatus = FT260_GetDevicePath(sDevicePath, sizeof(sDevicePath), i);

        if(NULL != wcsstr(sDevicePath, sOpenDeviceName))
        {
            // if find sOpenDeviceName substring in sDevicePath
            ftStatus = FT260_OpenByDevicePath(sDevicePath, &handle);
            if(FT260_OK != ftStatus)
            {
                // Open success
                printf("Open device by vid pid interface 0 string NG, status: %s\n", FT260StatusToString(ftStatus));
                FT260_Close(handle);
            }
            else
            {
                // Open fail
                printf("Open device by vid pid interface 0 string OK\n");
                wprintf(L"Open path %s\n", sDevicePath);
            }
            break;
        }
        else if(iDeveiceCount-1 == i)
        {
            // Not found
            printf("Not FT260 device\n");
        }
    }
    printf("\n");

    system("PAUSE");

    return 0;
}

bool IsFT260Dev(WCHAR* devPath)
{
    WCHAR findStr[100];
    swprintf_s(findStr, _countof(findStr), L"vid_%04x&pid_%04x",FT260_Vid,FT260_Vid);

    if(NULL == wcsstr(devPath, findStr))
    {
        return false;
    }
    else
    {
        return true;
    }
}

const char* FT260StatusToString(FT260_STATUS i)
{
    switch(i)
    {
    case  0:
        return sFT260Status[ 0].c_str();
    case  1:
        return sFT260Status[ 1].c_str();
    case  2:
        return sFT260Status[ 2].c_str();
    case  3:
        return sFT260Status[ 3].c_str();
    case  4:
        return sFT260Status[ 4].c_str();
    case  5:
        return sFT260Status[ 5].c_str();
    case  6:
        return sFT260Status[ 6].c_str();
    case  7:
        return sFT260Status[ 7].c_str();
    case  8:
        return sFT260Status[ 8].c_str();
    case  9:
        return sFT260Status[ 9].c_str();
    case 10:
        return sFT260Status[10].c_str();
    case 11:
        return sFT260Status[11].c_str();
    case 12:
        return sFT260Status[12].c_str();
    case 13:
        return sFT260Status[13].c_str();
    case 14:
        return sFT260Status[14].c_str();
    case 15:
        return sFT260Status[15].c_str();
    case 16:
        return sFT260Status[16].c_str();
    case 17:
        return sFT260Status[17].c_str();
    default:
        return "Not a valid FT260 status";
    }
}