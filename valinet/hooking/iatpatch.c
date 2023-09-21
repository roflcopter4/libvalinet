#include "Common/Common.h"
#include "iatpatch.h"

#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
# define ValinetDebug(...) printf(__VA_ARGS__)
#else
# define ValinetDebug(...)
#endif

// Credit to:
// https://blog.neteril.org/blog/2016/12/23/diverting-functions-windows-iat-patching/
// https://stackoverflow.com/questions/50973053/how-to-hook-delay-imports

//======================================================================================

static __forceinline BOOL
getModuleFromAddress(HMODULE hMod, HMODULE *module)
{
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)hMod, module);
}

static __forceinline bool
foundThunk(PIMAGE_THUNK_DATA thunk, PSTR funcName, HMODULE module, bool funcNameIsStr)
{
    if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
        return !funcNameIsStr && IMAGE_ORDINAL32(thunk->u1.Ordinal) == (DWORD)(uintptr_t)funcName;
    PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)module + thunk->u1.AddressOfData);
    return funcNameIsStr && StrIEq(byName->Name, funcName);
}

//======================================================================================

static PIMAGE_IMPORT_DESCRIPTOR
getImportDescriptor(HMODULE module, PSTR libName)
{
    // Get a reference to the import table to locate the kernel32 entry
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor =
        ImageDirectoryEntryToDataEx(module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL);

    // In the import table find the entry that corresponds to kernel32
    while (importDescriptor->Characteristics && importDescriptor->Name)
    {
        PSTR importName = (PSTR)((PBYTE)module + importDescriptor->Name);
        if (StrIEq(importName, libName)) {
            ValinetDebug("[PatchIAT] Found \"%s\" in IAT.\n", libName);
            return importDescriptor;
        }
        importDescriptor++;
    }

    return NULL;
}

static BOOL
patchThunkData(PIMAGE_THUNK_DATA thunk, PIMAGE_THUNK_DATA oldthunk,
               HMODULE module, PSTR funcName, uintptr_t hookAddr)
{
    bool funcNameIsStr = *((WORD *)&funcName + 1);

    // From the kernel32 import descriptor, go over its IAT thunks to find the one
    // used by the rest of the code to call GetProcAddress
    while (thunk->u1.Function) {
        PROC *funcStorage = (PROC *)&thunk->u1.Function;

        // Check if we've found the right thunk. Patch.
        if (foundThunk(oldthunk, funcName, module, funcNameIsStr)) {
            // Get the memory page where the info is stored
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery(funcStorage, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

            // Try to change the page to be writable if it's not already
            if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect))
                return FALSE;

            // Store our hook
            *funcStorage = (PROC)hookAddr;

            // Restore the old flag on the page
            DWORD dwOldProtect;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwOldProtect);
            return TRUE;
        }

        thunk++;
        oldthunk++;
    }

    return FALSE;
}

BOOL
VnPatchIAT(HMODULE hMod, PSTR libName, PSTR funcName, uintptr_t hookAddr)
{
    HMODULE module;
    // Increment module reference count to prevent other threads from unloading it
    // while we're working with it
    if (!getModuleFromAddress(hMod, &module))
        return FALSE;

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = getImportDescriptor(module, libName);
    if (!importDescriptor) {
        FreeLibrary(module);
        return FALSE;
    }
    bool funcNameIsStr = *((WORD *)&funcName + 1);

    PIMAGE_THUNK_DATA oldthunk = (PIMAGE_THUNK_DATA)((PBYTE)module + importDescriptor->OriginalFirstThunk);
    PIMAGE_THUNK_DATA thunk    = (PIMAGE_THUNK_DATA)((PBYTE)module + importDescriptor->FirstThunk);

    BOOL result = patchThunkData(thunk, oldthunk, module, funcName, hookAddr);
    ValinetDebug(funcNameIsStr ? "[PatchIAT] Patched \"%s\" in \"%s\" to %p.\n"
                               : "[PatchIAT] Patched %p in \"%s\" to %p.\n",
                 funcName, libName, (void *)hookAddr);

    FreeLibrary(module);
    return result;
}

//======================================================================================

static bool
patchDelayThunkData(PIMAGE_THUNK_DATA functhunk, uintptr_t hookAddr)
{
    DWORD oldProtect;
    if (!VirtualProtect(&functhunk->u1.Function, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    functhunk->u1.Function = hookAddr;
    VirtualProtect(&functhunk->u1.Function, sizeof(uintptr_t), oldProtect, &oldProtect);
    return true;
}

static PIMAGE_THUNK_DATA
findThunkData(PSTR funcName, HMODULE module, PIMAGE_DELAYLOAD_DESCRIPTOR dload, bool funcNameIsStr)
{
    PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((uintptr_t)module + dload->ImportNameTableRVA);
    PIMAGE_THUNK_DATA funcThunk  = (PIMAGE_THUNK_DATA)((uintptr_t)module + dload->ImportAddressTableRVA);

    while (firstThunk->u1.AddressOfData) {
        if (foundThunk(firstThunk, funcName, module, funcNameIsStr))
            return funcThunk;
        funcThunk++;
        firstThunk++;
    }

    return NULL;
}

BOOL
VnPatchDelayIAT(HMODULE hMod, PSTR libName, PSTR funcName, uintptr_t hookAddr)
{
    HMODULE module;
    if (!getModuleFromAddress(hMod, &module))
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((uintptr_t)module + dos->e_lfanew);
    PIMAGE_DELAYLOAD_DESCRIPTOR dload = (PIMAGE_DELAYLOAD_DESCRIPTOR)(
        (uintptr_t)module + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    bool funcNameIsStr = *((WORD *)&funcName + 1);

    while (dload->DllNameRVA) {
        char *dll = (char *)((uintptr_t)module + dload->DllNameRVA);
        if (StrIEq(dll, libName)) {
            ValinetDebug("[PatchDelayIAT] Found \"%s\" in IAT.\n", libName);
            PIMAGE_THUNK_DATA funcThunk = findThunkData(funcName, module, dload, funcNameIsStr);
            if (funcThunk && patchDelayThunkData(funcThunk, hookAddr)) {
                ValinetDebug(funcNameIsStr ? "[PatchDelayIAT] Patched \"%s\" in \"%s\" to %p.\n"
                                           : "[PatchDelayIAT] Patched %p in \"%s\" to %p.\n",
                             funcName, libName, (void *)hookAddr);
                FreeLibrary(module);
                return TRUE;
            }
        }

        dload++;
    }

    FreeLibrary(module);
    return FALSE;
}
