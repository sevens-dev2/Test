#pragma once
// lua_exec.h — v37 Metamorphic Lua Executor
//
// v36 → v37 changelog:
//   1. Metamorphic decoder (3 variants, anti-repeat selection).
//      - VariantA (35 bytes): v36-style, ror r9,8; inc r10; dec r11b
//      - VariantB (36 bytes): rol r9,8; lea r10,[r10+1] instead of inc
//      - VariantC (36 bytes): ror r9,8; inc r10; sub r11b,1 instead of dec
//      All three decode 8-byte-rotating-key encoded shellcode identically.
//      BuildPayload picks index via rdtsc; anti-repeat ensures no two
//      consecutive runs use the same variant.
//   2. Split W^X memory layout (lua_exec.cpp):
//      - Region A: PAGE_READWRITE holds ShellcodeParams (no X needed)
//      - Region B: PAGE_EXECUTE_READWRITE holds [NOPs|decoder|encoded]
//      - APC routine = B.base, arg1 = A.base. Shellcode entry still
//        reads params through rcx. Zero + free both regions after flip.
//   3. Lua payload (lua_payload.h) native-hash obfuscation:
//      - Preamble installs _G.__salt (random uint32) + _G.__h_raw table
//        with plain hashes XOR'd by salt at install time.
//      - _N(k) resolver returns __h_raw[k] XOR __salt.
//      - Literal hex native hashes no longer appear in executed source
//        after the preamble has run.
//   4. Lua kSpeedOn now sprint-gated:
//      - Requires IsControlPressed(0, INPUT_SPRINT=21).
//      - 8000ms max continuous active, 4000ms cooldown after a cycle.
//      - Looks like a human holding sprint, not a continuous override.
//   5. Lua preamble installs a debug.getinfo/traceback sanitizer that
//      filters out our injected thread sources from any ad-hoc scan.
//   6. Optional alternate dispatch (#ifdef V37_IOCOMPLETION_APC) using
//      NtCreateIoCompletion / NtSubmitIoCompletion; default off.
//   7. ShellcodeParams layout unchanged (static_asserts preserved).

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace LuaExecutor {

// ═══════════════════════════════════════════════════════════════
//  Pipeline result codes
// ═══════════════════════════════════════════════════════════════
enum class ExecResult : int {
    OK = 0,
    ProcessNotFound,
    OpenProcessFailed,
    LuaDllNotFound,
    DostringNotFound,
    LuaStateNotFound,
    AlertableThreadNotFound,
    AllocFailed,
    WriteFailed,
    ApcFailed,
    Timeout,
    LuaError,
    ScanBudgetExceeded,
    ScriptBlocked,
    ParamsAllocFailed,     // v37: Region A (RW) alloc failed
    PayloadAllocFailed     // v37: Region B (RX) alloc failed
};

// ═══════════════════════════════════════════════════════════════
//  Shellcode plain (45 bytes) — semantics unchanged since v34.
//    push rbx
//    mov  rbx, rcx           ; rbx = &ShellcodeParams
//    mov  rax, [rbx+0x00]
//    mov  rcx, [rbx+0x08]
//    lea  rdx, [rbx+0x20]
//    sub  rsp, 0x28
//    call rax
//    add  rsp, 0x28
//    mov  [rbx+0x2024], eax
//    mov  dword [rbx+0x2020], 1
//    xor  eax, eax
//    pop  rbx
//    ret
// ═══════════════════════════════════════════════════════════════
alignas(16) inline constexpr uint8_t kShellcodePlain[] = {
    0x53,
    0x48, 0x89, 0xCB,
    0x48, 0x8B, 0x03,
    0x48, 0x8B, 0x4B, 0x08,
    0x48, 0x8D, 0x53, 0x20,
    0x48, 0x83, 0xEC, 0x28,
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0x89, 0x83, 0x24, 0x20, 0x00, 0x00,
    0xC7, 0x83, 0x20, 0x20, 0x00, 0x00,
          0x01, 0x00, 0x00, 0x00,
    0x31, 0xC0,
    0x5B,
    0xC3
};
inline constexpr size_t kShellcodePlainSize = sizeof(kShellcodePlain); // 45

// ═══════════════════════════════════════════════════════════════
//  v37 Metamorphic Decoder Variants
//
//  All three decode 8-byte-rotating-key encoded shellcode with:
//    decoded[i] = encoded[i] XOR key[i % 8]
//
//  Registers (all variants): volatile only; rcx preserved.
//    r9   = 64-bit rotating key
//    r10  = pointer into encoded shellcode
//    r11b = countdown
//
//  Each variant stores its 8 key bytes as imm64 of the leading
//  mov r9, imm64 instruction (offsets 2..9).
// ═══════════════════════════════════════════════════════════════

// Variant A — ror r9,8; inc r10; dec r11b   (35 bytes)
//  [0..9]  49 B9 K0..K7              mov r9, imm64
//  [10..16] 4C 8D 15 12 00 00 00     lea r10, [rip+0x12]  (shellcode at offset 35)
//  [17..19] 41 B3 2D                 mov r11b, 45
//  [20..22] 45 30 0A                 xor byte [r10], r9b
//  [23..25] 49 FF C2                 inc r10
//  [26..29] 49 C1 C9 08              ror r9, 8
//  [30..32] 41 FE CB                 dec r11b
//  [33..34] 75 F1                    jnz -15  (→ offset 20)
alignas(16) inline constexpr uint8_t kDecoderVariantA[] = {
    0x49, 0xB9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8D, 0x15, 0x12, 0x00, 0x00, 0x00,
    0x41, 0xB3, 0x2D,
    0x45, 0x30, 0x0A,
    0x49, 0xFF, 0xC2,
    0x49, 0xC1, 0xC9, 0x08,
    0x41, 0xFE, 0xCB,
    0x75, 0xF1
};

// Variant B — rol r9,8; lea r10,[r10+1]; dec r11b  (36 bytes)
//  [0..9]   49 B9 K0..K7             mov r9, imm64
//  [10..16] 4C 8D 15 13 00 00 00     lea r10, [rip+0x13]  (shellcode at offset 36)
//  [17..19] 41 B3 2D                 mov r11b, 45
//  [20..22] 45 30 0A                 xor byte [r10], r9b
//  [23..26] 49 8D 52 01              lea r10, [r10+1]
//  [27..30] 49 C1 C1 08              rol r9, 8
//  [31..33] 41 FE CB                 dec r11b
//  [34..35] 75 F0                    jnz -16  (→ offset 20)
alignas(16) inline constexpr uint8_t kDecoderVariantB[] = {
    0x49, 0xB9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8D, 0x15, 0x13, 0x00, 0x00, 0x00,
    0x41, 0xB3, 0x2D,
    0x45, 0x30, 0x0A,
    0x49, 0x8D, 0x52, 0x01,
    0x49, 0xC1, 0xC1, 0x08,
    0x41, 0xFE, 0xCB,
    0x75, 0xF0
};

// Variant C — ror r9,8; inc r10; sub r11b,1   (36 bytes)
//  [0..9]   49 B9 K0..K7             mov r9, imm64
//  [10..16] 4C 8D 15 13 00 00 00     lea r10, [rip+0x13]  (shellcode at offset 36)
//  [17..19] 41 B3 2D                 mov r11b, 45
//  [20..22] 45 30 0A                 xor byte [r10], r9b
//  [23..25] 49 FF C2                 inc r10
//  [26..29] 49 C1 C9 08              ror r9, 8
//  [30..33] 41 80 EB 01              sub r11b, 1
//  [34..35] 75 F0                    jnz -16  (→ offset 20)
alignas(16) inline constexpr uint8_t kDecoderVariantC[] = {
    0x49, 0xB9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8D, 0x15, 0x13, 0x00, 0x00, 0x00,
    0x41, 0xB3, 0x2D,
    0x45, 0x30, 0x0A,
    0x49, 0xFF, 0xC2,
    0x49, 0xC1, 0xC9, 0x08,
    0x41, 0x80, 0xEB, 0x01,
    0x75, 0xF0
};

inline constexpr int    kDecoderVariantCount = 3;
inline constexpr size_t kDecoderVariantSizes[kDecoderVariantCount] = {
    sizeof(kDecoderVariantA),  // 35
    sizeof(kDecoderVariantB),  // 36
    sizeof(kDecoderVariantC)   // 36
};
inline constexpr size_t kDecoderMaxSize = 36;  // max of all variants
inline constexpr size_t kXorKeyOffset   = 2;   // all variants: 8 key bytes at offsets 2..9
inline constexpr size_t kXorKeyLength   = 8;

inline const uint8_t* GetDecoderVariant(int idx) {
    switch (idx) {
        case 0: return kDecoderVariantA;
        case 1: return kDecoderVariantB;
        case 2: return kDecoderVariantC;
    }
    return kDecoderVariantA;
}

// Payload total max: 3 NOPs + 36 decoder + 45 shellcode = 84 bytes
inline constexpr size_t kMaxPayloadSize = 3 + kDecoderMaxSize + kShellcodePlainSize;

// ═══════════════════════════════════════════════════════════════
//  ShellcodeParams — layout UNCHANGED since v34.
// ═══════════════════════════════════════════════════════════════
#pragma pack(push, 1)
struct alignas(8) ShellcodeParams {
    uint64_t pfnLuaLDostring;   // +0x00
    uint64_t pLuaState;         // +0x08
    uint64_t pfnVirtualFree;    // +0x10 (unused, compat)
    uint64_t pSelf;             // +0x18 (unused, compat)
    char     script[8192];      // +0x20
    uint32_t executed;          // +0x2020
    uint32_t luaError;          // +0x2024
};
#pragma pack(pop)

static_assert(offsetof(ShellcodeParams, pfnLuaLDostring) == 0x00);
static_assert(offsetof(ShellcodeParams, pLuaState)       == 0x08);
static_assert(offsetof(ShellcodeParams, script)          == 0x20);
static_assert(offsetof(ShellcodeParams, executed)        == 0x2020);
static_assert(offsetof(ShellcodeParams, luaError)        == 0x2024);
static_assert(sizeof(ShellcodeParams)                    == 0x2028);

// ═══════════════════════════════════════════════════════════════
//  v37 API
// ═══════════════════════════════════════════════════════════════

struct PayloadInfo {
    uint8_t* data;              // caller frees via delete[]
    size_t   size;              // total payload bytes
    uint8_t  xorKey[8];         // 8-byte rotating key
    int      nopCount;          // 0-3 NOP bytes before decoder
    int      decoderVariant;    // v37: which variant was used (0..2)
};

// Build polymorphic payload with metamorphic variant selection.
PayloadInfo BuildPayload();

// Full pipeline: find FiveM, resolve, inject (split W^X), execute Lua.
ExecResult Execute(const char* luaScript);

// Pipeline with an already-opened handle.
ExecResult ExecuteEx(HANDLE hProcess, DWORD pid, const char* luaScript);

DWORD FindFiveMPid();

struct LuaDllInfo {
    HMODULE   hModule;
    uintptr_t baseAddr;
    DWORD     size;
};
bool FindLuaDll(HANDLE hProcess, LuaDllInfo* out);

uintptr_t ResolveLuaDostring(HANDLE hProcess, const LuaDllInfo& dll);
uintptr_t FindLuaState(HANDLE hProcess, const LuaDllInfo& dll);
HANDLE    FindAlertableThread(DWORD pid);

} // namespace LuaExecutor
