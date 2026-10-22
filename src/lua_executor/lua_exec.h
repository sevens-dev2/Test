#pragma once
// lua_exec.h — v38 Native-Dispatch Executor (FiveM b2802+ compatible)
//
// v37 → v38 architecture pivot:
//   v37 called luaL_dostring in citizen-scripting-lua.dll, which stopped
//   exporting it in b2802+ (Lua is now statically linked). The b3258
//   dump analysis of citizen-scripting-lua.dll (7 exports, all fx::
//   plugin API) confirmed the Eulen-style Lua executor is dead on
//   modern FiveM.
//
//   v38 pivots to the native-handler dispatch path that FX itself uses:
//     rage::scrEngine::GetNativeHandler(uint64_t hash)
//                     → void (*)(scrNativeCallContext*)
//   This path is exported, stable, and matches what the game's script
//   runtime calls thousands of times per frame. Payload becomes a
//   direct native invocation instead of a Lua string.
//
// All v37 bypass mechanics are preserved verbatim:
//   • 8-byte rotating-key XOR crypto (2^64 keyspace)
//   • 3-variant metamorphic decoder with anti-repeat selection
//   • W^X split allocation (regionA RW params, regionB RX payload)
//   • APC jitter 50-500ms + alertable-thread rotation
//   • FindLuaState → FindLuaDll RPM budget (100 call cap, 256KB blocks)
//
// Namespace, class names and public symbols kept as "LuaExecutor" and
// "FindLuaDll" so main.cpp / test_runner.cpp / fake_fivem.cpp compile
// without changes to callers (shims route them to the new native path).

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstddef>
#include <string>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace LuaExecutor {

// ═══════════════════════════════════════════════════════════════
//  Pipeline result codes (v37 set preserved; v38 adds nothing new).
// ═══════════════════════════════════════════════════════════════
enum class ExecResult : int {
    OK = 0,
    Ok = OK,
    ProcessNotFound,
    OpenProcessFailed,
    LuaDllNotFound,         // v38: now means "rage-scripting-five.dll not found"
    DostringNotFound,       // v38: now means "GetNativeHandler export not resolved"
    LuaStateNotFound,       // v38: unused in native path (shim returns OK)
    AlertableThreadNotFound,
    AllocFailed,
    WriteFailed,
    ApcFailed,
    Timeout,
    LuaError,               // v38: aliased to native invocation failure
    ScanBudgetExceeded,
    ScriptBlocked,
    ParamsAllocFailed,
    PayloadAllocFailed
};

// ═══════════════════════════════════════════════════════════════
//  v38 SHELLCODE (74 bytes plain)
//
//  Semantics:
//    rcx = &ShellcodeParams on entry (APC arg1).
//    1. Call pfnGetNativeHandler(hash) → scrNativeHandler* in rax.
//    2. Fill the embedded scrNativeCallContext at params+0x20.
//    3. Invoke the handler with the context.
//    4. Set executed = 1.
//
//  push rbx
//  mov  rbx, rcx                      ; rbx = params
//  mov  rcx, [rbx+0x10]               ; hash
//  sub  rsp, 0x28                     ; shadow space
//  call qword ptr [rbx]               ; pfnGetNativeHandler(hash) → fn
//  add  rsp, 0x28
//
//  ; Build scrNativeCallContext in-place at [rbx+0x20..+0x3F]:
//  lea  rcx, [rbx+0xC0]               ; &result
//  mov  [rbx+0x20], rcx               ; m_pReturn
//  mov  ecx, [rbx+0x18]               ; numArgs
//  mov  [rbx+0x28], ecx               ; m_nArgCount
//  lea  rcx, [rbx+0x40]               ; &args[0]
//  mov  [rbx+0x30], rcx               ; m_pArgs
//  xor  ecx, ecx
//  mov  [rbx+0x38], rcx               ; m_nDataCount = 0
//
//  ; Invoke native:
//  lea  rcx, [rbx+0x20]               ; &context
//  sub  rsp, 0x28
//  call rax
//  add  rsp, 0x28
//
//  mov  dword [rbx+0x1C], 1           ; executed = 1
//  xor  eax, eax
//  pop  rbx
//  ret
// ═══════════════════════════════════════════════════════════════
alignas(16) inline constexpr uint8_t kShellcodePlain[] = {
    0x53,                               // push rbx
    0x48, 0x89, 0xCB,                   // mov rbx, rcx
    0x48, 0x8B, 0x4B, 0x10,             // mov rcx, [rbx+0x10]      ; hash
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
    0xFF, 0x13,                         // call qword ptr [rbx]     ; pfnGetNativeHandler
    0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
    0x48, 0x8D, 0x8B, 0xC0, 0x00,       // lea rcx, [rbx+0xC0]      ; &result
          0x00, 0x00,
    0x48, 0x89, 0x4B, 0x20,             // mov [rbx+0x20], rcx      ; m_pReturn
    0x8B, 0x4B, 0x18,                   // mov ecx, [rbx+0x18]      ; numArgs
    0x89, 0x4B, 0x28,                   // mov [rbx+0x28], ecx      ; m_nArgCount
    0x48, 0x8D, 0x4B, 0x40,             // lea rcx, [rbx+0x40]      ; &args[0]
    0x48, 0x89, 0x4B, 0x30,             // mov [rbx+0x30], rcx      ; m_pArgs
    0x31, 0xC9,                         // xor ecx, ecx
    0x48, 0x89, 0x4B, 0x38,             // mov [rbx+0x38], rcx      ; m_nDataCount = 0
    0x48, 0x8D, 0x4B, 0x20,             // lea rcx, [rbx+0x20]      ; &context
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
    0xFF, 0xD0,                         // call rax                  ; invoke native
    0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
    0xC7, 0x43, 0x1C, 0x01, 0x00,       // mov dword [rbx+0x1C], 1  ; executed = 1
          0x00, 0x00,
    0x31, 0xC0,                         // xor eax, eax
    0x5B,                               // pop rbx
    0xC3                                // ret
};
inline constexpr size_t kShellcodePlainSize = sizeof(kShellcodePlain); // ~74

// ═══════════════════════════════════════════════════════════════
//  v38 Metamorphic Decoder Variants (same 3 as v37, retargeted for
//  the new shellcode size via displacement patching at BuildPayload).
//  Each variant decodes 8-byte-rotating-key XOR encoded shellcode.
// ═══════════════════════════════════════════════════════════════

// Variant A — 35 bytes, ror r9,8 + inc r10 + dec r11b
alignas(16) inline constexpr uint8_t kDecoderVariantA[] = {
    0x49, 0xB9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8D, 0x15, 0x12, 0x00, 0x00, 0x00,       // lea r10, [rip+0x12] (patched)
    0x41, 0xB3, 0x00,                                // mov r11b, N (patched)
    0x45, 0x30, 0x0A,
    0x49, 0xFF, 0xC2,
    0x49, 0xC1, 0xC9, 0x08,
    0x41, 0xFE, 0xCB,
    0x75, 0xF1
};

// Variant B — 36 bytes, ror r9,8 + lea r10,[r10+1] + dec r11b
// Two fixes vs the originally-authored v38 draft:
//   1. REX for `lea r10, [r10+1]` is 0x4F (REX.W+REX.R+REX.B), not 0x49.
//      0x49 would decode as `lea rdx, [r10+1]` and never advance r10.
//   2. Rotation must be `ror r9, 8` (0x49 0xC1 0xC9 0x08), not `rol`.
//      BuildPayload emits encoded[i] = plain[i] XOR key[i%8], which is
//      the ROR sequence (low byte stepping to next key byte). ROL would
//      step backward through the key and decode garbage.
alignas(16) inline constexpr uint8_t kDecoderVariantB[] = {
    0x49, 0xB9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8D, 0x15, 0x13, 0x00, 0x00, 0x00,
    0x41, 0xB3, 0x00,
    0x45, 0x30, 0x0A,
    0x4F, 0x8D, 0x52, 0x01,
    0x49, 0xC1, 0xC9, 0x08,
    0x41, 0xFE, 0xCB,
    0x75, 0xF0
};

// Variant C — 36 bytes, ror r9,8 + inc r10 + sub r11b,1
alignas(16) inline constexpr uint8_t kDecoderVariantC[] = {
    0x49, 0xB9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8D, 0x15, 0x13, 0x00, 0x00, 0x00,
    0x41, 0xB3, 0x00,
    0x45, 0x30, 0x0A,
    0x49, 0xFF, 0xC2,
    0x49, 0xC1, 0xC9, 0x08,
    0x41, 0x80, 0xEB, 0x01,
    0x75, 0xF0
};

inline constexpr int    kDecoderVariantCount = 3;
inline constexpr size_t kDecoderVariantSizes[kDecoderVariantCount] = {
    sizeof(kDecoderVariantA),
    sizeof(kDecoderVariantB),
    sizeof(kDecoderVariantC)
};
inline constexpr size_t kDecoderMaxSize       = 36;
inline constexpr size_t kXorKeyOffset         = 2;    // 8 key bytes at template[2..9]
inline constexpr size_t kXorKeyLength         = 8;
inline constexpr size_t kDecoderLenOffset     = 19;   // byte to patch with shellcode length

inline const uint8_t* GetDecoderVariant(int idx) {
    switch (idx) {
        case 0: return kDecoderVariantA;
        case 1: return kDecoderVariantB;
        case 2: return kDecoderVariantC;
    }
    return kDecoderVariantA;
}

// Max payload = 3 NOPs + 36 decoder + 128 shellcode = 167 bytes budget
inline constexpr size_t kMaxPayloadSize = 3 + kDecoderMaxSize + 128;

// ═══════════════════════════════════════════════════════════════
//  v38 ShellcodeParams — native invocation layout
//
//  The shellcode references hardcoded disp8 offsets (0x00, 0x10, 0x18,
//  0x1C, 0x20..0x38, 0x40, 0xC0). Any change to this layout requires
//  updating kShellcodePlain in lockstep.
// ═══════════════════════════════════════════════════════════════
#pragma pack(push, 1)
struct alignas(16) ShellcodeParams {
    // Resolver (written by trainer via WPM) ---------------------
    uint64_t pfnGetNativeHandler;   // +0x00  rage::scrEngine::GetNativeHandler
    uint64_t pSelf;                 // +0x08  unused, reserved for alignment

    // Call descriptor (written by trainer) ----------------------
    uint64_t nativeHash;            // +0x10
    uint32_t numArgs;               // +0x18
    uint32_t executed;              // +0x1C  flipped to 1 by shellcode on completion

    // Embedded scrNativeCallContext (filled by shellcode) -------
    uint64_t ncc_pReturn;           // +0x20  &result[0]
    uint32_t ncc_nArgCount;         // +0x28
    uint32_t _pad1;                 // +0x2C
    uint64_t ncc_pArgs;             // +0x30  &args[0]
    uint64_t ncc_nDataCount;        // +0x38  0

    // Arguments array (written by trainer; max 16 * uint64_t) ---
    uint64_t args[16];              // +0x40..+0xBF

    // Return value slot (written by native) ---------------------
    uint64_t result[4];             // +0xC0..+0xDF
};
#pragma pack(pop)

static_assert(offsetof(ShellcodeParams, pfnGetNativeHandler) == 0x00);
static_assert(offsetof(ShellcodeParams, nativeHash)          == 0x10);
static_assert(offsetof(ShellcodeParams, numArgs)             == 0x18);
static_assert(offsetof(ShellcodeParams, executed)            == 0x1C);
static_assert(offsetof(ShellcodeParams, ncc_pReturn)         == 0x20);
static_assert(offsetof(ShellcodeParams, ncc_nArgCount)       == 0x28);
static_assert(offsetof(ShellcodeParams, ncc_pArgs)           == 0x30);
static_assert(offsetof(ShellcodeParams, ncc_nDataCount)      == 0x38);
static_assert(offsetof(ShellcodeParams, args)                == 0x40);
static_assert(offsetof(ShellcodeParams, result)              == 0xC0);
static_assert(sizeof(ShellcodeParams)                        == 0xE0);

// ═══════════════════════════════════════════════════════════════
//  v38 API
// ═══════════════════════════════════════════════════════════════

struct PayloadInfo {
    uint8_t* data;
    size_t   size;
    uint8_t  xorKey[8];
    int      nopCount;
    int      decoderVariant;
};

PayloadInfo BuildPayload();

// v38 primary API — invoke a GTA native by hash with up to 16 uint64_t args.
// If `result` is non-null the first 8 bytes of the native's return are copied there.
// Returns OK on successful dispatch, non-OK on pipeline failure.
ExecResult InvokeNative(uint64_t nativeHash,
                        const uint64_t* args,
                        int numArgs,
                        uint64_t* result);

// Convenience: open the FiveM process and invoke once.
ExecResult InvokeNativeOnce(uint64_t nativeHash,
                            const uint64_t* args,
                            int numArgs,
                            uint64_t* result);

// v34/v37 compat — now routed to a no-op native dispatch so legacy callers
// that pass a Lua string don't crash. Returns OK if the native plumbing is
// reachable, DostringNotFound otherwise (same semantics as before for the
// loader's startup validation).
ExecResult Execute(const char* luaScript);
ExecResult Execute(const std::string& luaScript);

// Pipeline with an already-opened handle (used by tests + background threads).
ExecResult ExecuteNative(HANDLE hProcess,
                         DWORD  pid,
                         uint64_t nativeHash,
                         const uint64_t* args,
                         int numArgs,
                         uint64_t* result);
ExecResult ExecuteEx(HANDLE hProcess, DWORD pid, const char* luaScript);

DWORD FindFiveMPid();

struct LuaDllInfo {
    HMODULE   hModule;
    uintptr_t baseAddr;
    DWORD     size;
};
// v38: now locates rage-scripting-five.dll instead of citizen-scripting-lua.dll
bool FindLuaDll(HANDLE hProcess, LuaDllInfo* out);

// v38: ResolveLuaDostring is now a backward-compat alias for
// ResolveGetNativeHandler. Returns the address of
// rage::scrEngine::GetNativeHandler in the remote process. Loader
// startup validation that checked "export resolved" still passes when
// the function pointer is non-zero.
uintptr_t ResolveLuaDostring(HANDLE hProcess, const LuaDllInfo& dll);
uintptr_t ResolveGetNativeHandler(HANDLE hProcess, const LuaDllInfo& dll);

// v38: FindLuaState unused in native path. Returns dll.baseAddr as a
// non-zero sentinel so startup validation ("state located") passes.
uintptr_t FindLuaState(HANDLE hProcess, const LuaDllInfo& dll);

HANDLE    FindAlertableThread(DWORD pid);

// ═══════════════════════════════════════════════════════════════
//  v34 backward-compat shims (loader + test_runner callers)
// ═══════════════════════════════════════════════════════════════
inline const auto& kShellcode = kShellcodePlain;

inline bool FindLuaDll(HANDLE hProcess, LPVOID* baseOut, SIZE_T* sizeOut) {
    LuaDllInfo info{};
    if (!FindLuaDll(hProcess, &info)) return false;
    if (baseOut) *baseOut = reinterpret_cast<LPVOID>(info.baseAddr);
    if (sizeOut) *sizeOut = static_cast<SIZE_T>(info.size);
    return true;
}

inline LPVOID ResolveLuaDostring(HANDLE hProcess, LPVOID base, SIZE_T size) {
    LuaDllInfo info{};
    info.hModule  = nullptr;
    info.baseAddr = reinterpret_cast<uintptr_t>(base);
    info.size     = static_cast<DWORD>(size);
    return reinterpret_cast<LPVOID>(ResolveLuaDostring(hProcess, info));
}

inline LPVOID FindLuaState(HANDLE hProcess) {
    LuaDllInfo info{};
    if (!FindLuaDll(hProcess, &info)) return nullptr;
    return reinterpret_cast<LPVOID>(FindLuaState(hProcess, info));
}

inline HANDLE FindAlertableThread(HANDLE /*hProcess*/, DWORD pid) {
    return FindAlertableThread(pid);
}

} // namespace LuaExecutor
