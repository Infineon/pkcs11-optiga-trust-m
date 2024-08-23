// SPDX-FileCopyrightText: 2024 Infineon Technologies AG
//
// SPDX-License-Identifier: MIT

#ifndef LOG_H
#define LOG_H

// For debugging only, comment these 2 lines for release version!
//~ #undef DEBUG // !!!JC
//~ #define DEBUG // !!!JC

#ifdef DEBUG

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PKCS11_PRINT Log  //printf
#define PKCS11_DEBUG Log  //printf
#define PKCS11_WARNING_PRINT printf
#define HEXDUMP HexASCII
#define LOGOPEN LogOpen();
#define LOGCLOSE LogClose();
#define LOG_AUTO_FLUSH

extern FILE *stream_log;
extern char debug_message[256];

void LogOpen(void);
void LogFlush(void);
void LogClose(void);
void Log(char *format, ...);
void HexDump(char *message, uint8_t *data, int len);
void HexASCII(char *message, uint8_t *data, int len);

#else

#define PKCS11_PRINT
#define PKCS11_DEBUG
#define PKCS11_WARNING_PRINT
#define HEXDUMP
#define LOGOPEN
#define LOGCLOSE

#endif

#endif  // LOG_H
