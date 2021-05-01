
#define PAGE_SIZE 0x1000

#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (ULONG)(_size_))
#define M_REALLOC(_addr_, _size_) LocalReAlloc((_addr_), (_size_), LMEM_MOVEABLE | LMEM_ZEROINIT)
#define M_FREE(_addr_) LocalFree((_addr_))

#define RVATOVA(_addr_, _x_) ((PUCHAR)(_addr_) + (_x_))

#define _ALIGN_DOWN(_x_, _align_) ((_x_) & ~((_align_) - 1))

#define _ALIGN_UP(_x_, _align_) (((_x_) & ((_align_) - 1)) ? _ALIGN_DOWN((_x_), (_align_)) + (_align_) : (_x_))

#define GET_IMPORT(_lib_, _name_)                               \
                                                                \
    func_##_name_ f_##_name_ = (func_##_name_)GetProcAddress(   \
        GetModuleHandle((_lib_)), #_name_);

#define GET_NATIVE(_name_) GET_IMPORT("ntdll.dll", _name_)                                                               

typedef BOOL(WINAPI * func_IsWindows8_1OrGreater)(void);

typedef BOOL(WINAPI * func_IsWow64Process)(
    HANDLE hProcess,
    PBOOL Wow64Process
);

#define IFMT32 "0x%.8x"
#define IFMT64 "0x%.16I64x"

#define IFMT32_W L"0x%.8x"
#define IFMT64_W L"0x%.16I64x"

#ifdef _X86_

#define IFMT IFMT32
#define IFMT_W IFMT32_W

#else _AMD64_

#define IFMT IFMT64
#define IFMT_W IFMT64_W

#endif
