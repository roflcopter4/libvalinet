#pragma once
#ifndef LIBVALINET_PDB_PDB_H_
#define LIBVALINET_PDB_PDB_H_
//
// pdb includes:
// * pdbdump - Small tool to list and query symbols in PDB files.
//   original source code: https://gist.github.com/mridgers/2968595
// * PDBDownloader
//   original source code: https://github.com/rajkumar-rangaraj/PDB-Downloader

#include <valinet/internet/get.h>
#include <stdio.h>
#include <Windows.h>
#include <stdint.h>
#include <DbgHelp.h>
#include <Shlwapi.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")

#define ASSERT(x, m, ...)                              \
      do {                                             \
            if (!(x)) {                                \
                  fprintf(stderr, (m), ##__VA_ARGS__); \
                  exit(1);                             \
            }                                          \
      } while (0)

#define VN_PDB_ONE_MB                       (10240 * 10240)
#define VN_PDB_ADDRESS_OFFSET               0x400000
#define VN_PDB_SYMBOL_HOSTNAME              "msdl.microsoft.com"
#define VN_PDB_SYMBOL_WEB                   "/download/symbols/"
#define VN_PDB_USER_AGENT                   "Microsoft-Symbol-Server/10.0.10036.206"
#define VN_PDB_FORM_HEADERS                 "Content-Type: application/octet-stream;\r\n"
#define VN_PDB_DOWNLOAD_FILE_BUFFER_SIZE    4096

// https://deplinenoise.wordpress.com/2013/06/14/getting-your-pdb-name-from-a-running-executable-windows/
typedef struct PdbInfo {
    DWORD Signature;
    GUID  Guid;
    DWORD Age;
    char  PdbFileName[1];
} PdbInfo;

enum e_mode {
    e_mode_resolve_stdin,
    e_mode_enum_symbols,
};

enum e_enum_type {
    e_enum_type_symbols,
    e_enum_type_types,
};

typedef struct sym_info {
    DWORD64 addr;
    int     size;
    char   *name;
    char   *file;
    int     tag  : 8;
    int     line : 24;
} sym_info_t;

typedef struct pool {
    char *base;
    int   committed;
    int   size;
    int   used;
} pool_t;

typedef int(sort_func_t)(const sym_info_t *, const sym_info_t *);

extern HANDLE           g_handle;
extern enum e_enum_type g_enum_type;
extern enum e_mode      g_mode;
extern int              g_csv_output;
extern int              g_page_size;
extern int              g_sym_count;
extern pool_t           g_string_pool;
extern pool_t           g_symbol_pool;
extern const char      *g_sym_tag_names[]; /* ...at end of file */

extern BOOL CALLBACK enum_proc(SYMBOL_INFO const *info, ULONG size, void *param);
extern INT           VnDownloadSymbols(HMODULE hModule, char const *dllName, char *szLibPath, UINT sizeLibPath);
extern INT           VnGetSymbols(const char *pdb_file, DWORD *addresses, char const *const *symbols, DWORD numOfSymbols);
extern int           create_pools(uintptr_t base_addr);
extern int           fileExists(char const *file);
extern uintptr_t     load_module(const char *pdb_file);
extern void          dbghelp_to_sym_info(SYMBOL_INFO const *info, sym_info_t *sym_info);
extern void          pool_clear(pool_t *pool);
extern void          pool_create(pool_t *pool, int size);
extern void          pool_destroy(pool_t const *pool);
extern void         *pool_alloc(pool_t *pool, int size);

#endif
