// SPDX-FileCopyrightText: 2024 Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#ifdef DEBUG
#include "log.h"

#include <ctype.h>

FILE *stream_log = NULL;
char debug_message[256];

/*-------------------------------------------------------------------------------
      Create log file
  -------------------------------------------------------------------------------*/
void LogOpen(void) {
    static char *openmode = "a+";
    char filename[256];
    time_t currenttime;
    time(&currenttime);
    struct tm *loctime;

    if (stream_log != NULL)
        return;

    sprintf(filename, "pkcs11-OptigaTrustM.log");
    if ((stream_log = fopen(filename, openmode)) == NULL) {
        printf("ERROR: LogOpen: Can't create file '%s'\n\n", filename);
    } else {
        loctime = localtime(&currenttime);
        sprintf(
            filename,
            "%04d-%02d-%02d %02d-%02d-%02d",
            loctime->tm_year + 1900,
            loctime->tm_mon + 1,
            loctime->tm_mday,
            loctime->tm_hour,
            loctime->tm_min,
            loctime->tm_sec
        );
        Log("================== %s   Optiga Trust M PKCS#11 module =================\r\n",
            filename);
    }
}
/*-------------------------------------------------------------------------------
      Flush log file
  -------------------------------------------------------------------------------*/
void LogFlush(void) {
    if (stream_log != NULL)
        fflush(stream_log);
}
/*-------------------------------------------------------------------------------
      Print formatted data (as printf does) to a file (if it is opened)
  -------------------------------------------------------------------------------*/
void Log(char *format, ...) {
    if (stream_log == NULL)
        return;
    va_list arglist;
    va_start(arglist, format);
    vfprintf(stream_log, format, arglist);
    va_end(arglist);
#ifdef LOG_AUTO_FLUSH
    LogFlush();
#endif
}
/*-------------------------------------------------------------------------------
      Close log file
  -------------------------------------------------------------------------------*/
void LogClose(void) {
    if (stream_log != NULL)
        fclose(stream_log);
    stream_log = NULL;
}

/*-------------------------------------------------------------------------
   Hex dump data to screen (if debug mode is enabled)
   1 - message
   2 - parameter: pointer to dumped data
   3 - parameter: dumped data length
  -------------------------------------------------------------------------*/
void HexDump(char *message, uint8_t *data, int len) {
    int i, j;
    char str[200] = {0};

    if (message && strlen(message) > 0) {
        strncpy(str, message, sizeof(str) - (16 * 3) - 3);
    }
    int slen = (int)strlen(str);

    for (i = 0; i < len; i++, data++) {
        if ((i % 16) == 0 && i != 0) {
            Log("%s\n", str);
            for (j = 0; j < slen; j++)
                str[j] = ' ';  // Add spaces in front of 2... lines
            str[j] = 0;
        }
        sprintf(str + slen + (i % 16) * 3, "%.2X ", *data);
    }
    Log("%s\n", str);
}
/*-------------------------------------------------------------------------
   Hex + ASCII dump data to screen (in debug mode) and/or log file (if open)
   (without address)
   1 - message
   2 - parameter: pointer to dumped data
   3 - parameter: dumped data length
  -------------------------------------------------------------------------*/
void HexASCII(char *message, uint8_t *data, int len) {
    int i, j, k = 0;
    char str[200] = {0};
    char asc[100];

    if (message && strlen(message) > 0) {
        strncpy(str, message, sizeof(str) - (16 * 3) - 3);
    }
    int slen = (int)strlen(str);

    for (i = 0; i < len; i++, data++) {
        if ((i % 16) == 0 && i != 0) {
            Log("%s %s\n", str, asc);
            for (j = 0; j < slen; j++)
                str[j] = ' ';  // Add spaces in front of 2... lines
            str[j] = 0;
            k = 0;
        }
        sprintf(str + slen + (i % 16) * 3, "%.2X ", *data);
        if (isprint((int)*data))
            asc[k] = *data;
        else
            asc[k] = '.';
        asc[++k] = 0;
    }
    for (j = k; j < 16; j++)
        strcat(str, "   ");  // Add spaces in the last line
    Log("%s %s\n", str, asc);
}

#endif
