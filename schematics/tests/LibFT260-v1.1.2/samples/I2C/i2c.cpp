/**
* @file i2c.cpp
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

//------------------------------------------------------------------------------
// main
//------------------------------------------------------------------------------
int main(void)
{
    FT260_HANDLE mhandle1 = INVALID_HANDLE_VALUE;
    FT260_STATUS ftStatus = FT260_OK;
    DWORD devNum = 0;
    FT260_CreateDeviceList(&devNum);

    FT260_Open(0, &mhandle1);

    unsigned char writeData[] = { 0xaa, 0xbb, 0x00, 0x01, 0x55, 0x66 };

    ftStatus = FT260_I2CMaster_Init(mhandle1, 100);

    while (1)
    {
        printf("I2C app (1)Read (2)Write (3)Reset (4)Get status (5)Quit>>>> \n");
        char input = getch();

        if (input == '1')
        {
            DWORD readLength = 0;
            unsigned long len;
            char buffer[5];
            unsigned char *readData;

            printf("How many bytes do you want to read?\n");
            printf ("Enter an unsigned number: ");
            fgets (buffer, 256, stdin);
            len = strtoul (buffer, NULL, 0);
            if (len <= 0)
            {
                printf ("It is not a vaild number\n");
                continue;
            }
            readData = (unsigned char *)malloc(len);

            ftStatus = FT260_I2CMaster_Read(mhandle1, 34, FT260_I2C_START_AND_STOP, readData, len , &readLength, 5000);
            printf("FT260_I2C_Read  ftStatus: %d  Read Length: %d\n\n", ftStatus, readLength);    // ftStatus = 0 is FT260_OK
            for(DWORD i=0; i< len; i++)
                printf("%02x", readData[i]);
            printf("\n");
            free(readData);
        }
        else if (input == '2')
        {
            DWORD writeLength = 0;
            ftStatus = FT260_I2CMaster_Write(mhandle1, 34, FT260_I2C_START_AND_STOP, writeData, sizeof(writeData), &writeLength);
            printf("FT260_I2C_Write  ftStatus: %d  Write Length: %d\n\n", ftStatus, writeLength);
        }
        else if (input == '3')
        {
            ftStatus = FT260_I2CMaster_Reset(mhandle1);
            printf("FT260_I2C_Reset  ftStatus: %d\n\n", ftStatus);
        }
        else if (input == '4')
        {
            /* I2C Master Controller Status (I2Cstauts variable)
             *   bit 0 = controller busy: all other status bits invalid
             *   bit 1 = error condition
             *   bit 2 = slave address was not acknowledged during last operation
             *   bit 3 = data not acknowledged during last operation
             *   bit 4 = arbitration lost during last operation
             *   bit 5 = controller idle
             *   bit 6 = bus busy
             */
            uint8 I2Cstauts;
            ftStatus = FT260_I2CMaster_GetStatus(mhandle1, &I2Cstauts);
            printf("FT260_I2C_GetStatus  ftStatus: %d, I2Cstauts: %d\n\n", ftStatus, I2Cstauts);
        }
        else if (input == '5')
        {
            printf("Quit\n\n");
            break;
        }
    }

    system("PAUSE");
    return 0;
}
