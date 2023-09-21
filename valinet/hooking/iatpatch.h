#pragma once
#ifndef LIBVALINET_HOOKING_IATPATCH_H_
#define LIBVALINET_HOOKING_IATPATCH_H_

#include <Windows.h>
#include <DbgHelp.h>
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
# undef _LIBVALINET_DEBUG_HOOKING_IATPATCH
# include <stdio.h>
# include <conio.h>
#endif

/**
 * \brief Patch the Import Address Table (IAT) of a Windows module with a hook function.
 * \param hMod The module address
 * \param libName 
 * \param funcName 
 * \param hookAddr 
 * \return 
 */
extern BOOL VnPatchIAT(HMODULE hMod, PSTR libName, PSTR funcName, uintptr_t hookAddr);
extern BOOL VnPatchDelayIAT(HMODULE hMod, PSTR libName, PSTR funcName, uintptr_t hookAddr);

#endif