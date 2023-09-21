#pragma once
#ifndef LIBVALINET_INTERNET_GET_H_
#define LIBVALINET_INTERNET_GET_H_
#include <stdio.h>
#include <Windows.h>
#include <Wininet.h>
#pragma comment(lib, "Wininet.lib")

inline DWORD VnDownloadFile(
    char const   *filename,
    char const   *hostname,
    char const   *path,
    char const   *userAgent,
    INTERNET_PORT nServerPort,
    DWORD         dwService,
    char const   *referrer,
    char const   *headers,
    DWORD         bufsiz
)
{
    DWORD     dwRet     = 0;
    HINTERNET hInternet = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {
        HINTERNET hConnect = InternetConnectA(hInternet, hostname, nServerPort, NULL, NULL, dwService, 0, 0);
        if (hConnect) {
            HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path, NULL, referrer, NULL, 0, 0);
            if (hRequest) {
                char data[1] = "";
                if (HttpSendRequestA(hRequest, headers, strlen(headers), data, strlen(data) * sizeof(char))) {
                    FILE *f = NULL;
                    if (fopen_s(&f, filename, "wb")) {
                        dwRet = 7;
                    } else {
                        BYTE *buffer = (BYTE *)malloc(bufsiz);
                        if (buffer == NULL) {
                            dwRet = 6;
                        } else {
                            DWORD dwRead;
                            BOOL  bRet;
                            while ((bRet = InternetReadFile(hRequest, buffer, bufsiz, &dwRead))) {
                                if (dwRead == 0)
                                    break;
                                fwrite(buffer, sizeof(BYTE), dwRead, f);
                                dwRead = 0;
                            }
                            if (bRet == FALSE)
                                dwRet = 5;
                            free(buffer);
                        }
                        fclose(f);
                    }
                } else {
                    dwRet = 4;
                }
                InternetCloseHandle(hRequest);
            } else {
                dwRet = 3;
            }
            InternetCloseHandle(hConnect);
        } else {
            dwRet = 2;
        }
        InternetCloseHandle(hInternet);
    } else {
        dwRet = 1;
    }

    return dwRet;
}

#endif