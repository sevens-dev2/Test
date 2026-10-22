// lua_exec.cpp — v38 Native-Dispatch Executor (implementation)
//
// Routes external invocation into FiveM via
//   rage::scrEngine::GetNativeHandler(hash) → scrNativeHandler*
// instead of the dead-in-b2802+ Lua path.

#include "lua_exec.h"

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <intrin.h>

typedef NTSTATUS (NTAPI* pfnNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID  ApcRoutine,
    PVOID  ApcArgument1,
    PVOID  ApcArgument2,
    PVOID  ApcArgument3
);

namespace LuaExecutor {

// Forward decl so ResolveGetNativeHandler can trigger it on failure.
void DumpAllCandidateExports(HANDLE hProcess);

// ═══════════════════════════════════════════════════════════════
//  debug log (world-writable path — appends per step)
// ═══════════════════════════════════════════════════════════════
static inline void dbg_log(const char* msg) {
    HANDLE h = CreateFileA("C:\\Users\\Public\\fivem_debug.log",
                           FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME t; GetLocalTime(&t);
    char line[1024];
    int n = snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d] %s\r\n",
                     t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, msg);
    DWORD w = 0;
    SetFilePointer(h, 0, nullptr, FILE_END);
    WriteFile(h, line, (DWORD)n, &w, nullptr);
    CloseHandle(h);
}

// ═══════════════════════════════════════════════════════════════
//  BuildPayload — generates a polymorphic payload
//    [NOPs] + [decoder variant with inline 8-byte key + length patch]
//          + [shellcode XOR'd with the key]
// ═══════════════════════════════════════════════════════════════
PayloadInfo BuildPayload() {
    PayloadInfo info{};

    // 8-byte key via xorshift64* mix (never all-zero).
    uint64_t mix = __rdtsc()
                 ^ GetTickCount64()
                 ^ reinterpret_cast<uintptr_t>(&info)
                 ^ (static_cast<uint64_t>(GetCurrentThreadId()) << 17);
    bool allZero;
    do {
        allZero = true;
        for (int i = 0; i < 8; i++) {
            mix ^= mix << 13;
            mix ^= mix >> 7;
            mix ^= mix << 17;
            mix ^= __rdtsc();
            info.xorKey[i] = static_cast<uint8_t>(mix >> ((i * 8) & 0x3F));
            if (info.xorKey[i] != 0) allZero = false;
        }
    } while (allZero);

    // Anti-repeat variant selection
    static int s_lastVariant = -1;
    int pick = static_cast<int>((__rdtsc() >> 3) % kDecoderVariantCount);
    if (pick == s_lastVariant) pick = (pick + 1) % kDecoderVariantCount;
    s_lastVariant = pick;
    info.decoderVariant = pick;

    const uint8_t* variant     = GetDecoderVariant(pick);
    const size_t   variantSize = kDecoderVariantSizes[pick];

    // 0-3 NOP padding before decoder
    info.nopCount = static_cast<int>(GetTickCount() & 0x3);

    info.size = static_cast<size_t>(info.nopCount) + variantSize + kShellcodePlainSize;
    info.data = new uint8_t[info.size];

    size_t pos = 0;
    for (int i = 0; i < info.nopCount; i++)
        info.data[pos++] = 0x90;

    // Copy decoder template, patch 8-byte key AND the length byte
    memcpy(info.data + pos, variant, variantSize);
    for (size_t i = 0; i < kXorKeyLength; i++)
        info.data[pos + kXorKeyOffset + i] = info.xorKey[i];
    // Patch loop counter to match the new shellcode length
    info.data[pos + kDecoderLenOffset] = static_cast<uint8_t>(kShellcodePlainSize);
    pos += variantSize;

    // Encode shellcode
    for (size_t i = 0; i < kShellcodePlainSize; i++)
        info.data[pos++] = kShellcodePlain[i] ^ info.xorKey[i % kXorKeyLength];

    return info;
}

// ═══════════════════════════════════════════════════════════════
//  FindFiveMPid — matches versioned FiveM GTA process names.
// ═══════════════════════════════════════════════════════════════
static bool IsFiveMGameProcessName(const wchar_t* name) {
    if (!name) return false;
    if (_wcsicmp(name, L"GTA5.exe") == 0) return true;
    if (_wcsnicmp(name, L"FiveM", 5) != 0) return false;
    const size_t len = wcslen(name);
    for (size_t i = 0; i + 10 <= len; i++) {
        if (_wcsnicmp(name + i, L"GTAProcess", 10) == 0) return true;
    }
    return false;
}

DWORD FindFiveMPid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (IsFiveMGameProcessName(pe.szExeFile)) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// ═══════════════════════════════════════════════════════════════
//  FindLuaDll (v38: now finds rage-scripting-five.dll)
//
//  Priority:
//    1. rage-scripting-five.dll  (v38 native dispatch host)
//    2. legacy exact names (lua54.dll, citizen-scripting-lua54.dll)
//    3. fuzzy lua54 / scripting-lua
// ═══════════════════════════════════════════════════════════════
static bool w_contains_ci(const WCHAR* hay, const WCHAR* needle) {
    if (!hay || !needle) return false;
    size_t nlen = wcslen(needle);
    if (nlen == 0) return true;
    for (size_t i = 0; hay[i]; i++) {
        if (_wcsnicmp(hay + i, needle, nlen) == 0) return true;
    }
    return false;
}

static void dump_line_utf8(HANDLE hFile, const WCHAR* w) {
    char buf[MAX_PATH * 2];
    int bl = WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, sizeof(buf) - 2, nullptr, nullptr);
    if (bl > 0) {
        buf[bl - 1] = '\r';
        buf[bl]     = '\n';
        DWORD w2 = 0;
        WriteFile(hFile, buf, bl + 1, &w2, nullptr);
    }
}

bool FindLuaDll(HANDLE hProcess, LuaDllInfo* out) {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProcess, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
            return false;
    }
    DWORD count = needed / sizeof(HMODULE);

    // Dump the module list for diagnostics
    WCHAR dumpPath[MAX_PATH];
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD tn = GetEnvironmentVariableW(L"TEMP", dumpPath, MAX_PATH);
    if (tn > 0 && tn < MAX_PATH - 32) {
        wcscat_s(dumpPath, MAX_PATH, L"\\fivem_modules.txt");
        hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            char header[256];
            int hl = snprintf(header, sizeof(header),
                "FiveMMenu v38 FindLuaDll - %lu modulos no processo FiveM\r\n"
                "Alvo primario: rage-scripting-five.dll\r\n\r\n", count);
            DWORD w = 0;
            WriteFile(hFile, header, hl, &w, nullptr);
        }
    }

    // Pass 1: rage-scripting-five.dll (v38 primary)
    for (DWORD i = 0; i < count; i++) {
        WCHAR name[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, mods[i], name, MAX_PATH)) continue;
        WCHAR* base = wcsrchr(name, L'\\');
        if (!base) base = name; else base++;
        if (_wcsicmp(base, L"rage-scripting-five.dll") == 0) {
            MODULEINFO mi{};
            GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi));
            out->hModule  = mods[i];
            out->baseAddr = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            out->size     = mi.SizeOfImage;
            if (hFile != INVALID_HANDLE_VALUE) {
                const char tag[] = "MATCH: rage-scripting-five.dll\r\n";
                DWORD w = 0; WriteFile(hFile, tag, sizeof(tag)-1, &w, nullptr);
                dump_line_utf8(hFile, name);
                CloseHandle(hFile);
            }
            return true;
        }
    }

    // Pass 2: legacy v37 lua names (preserved for pre-b2802 builds)
    const WCHAR* legacy[] = {
        L"citizen-scripting-lua54.dll",
        L"lua54.dll",
        L"citizen-scripting-lua.dll"
    };
    for (DWORD i = 0; i < count; i++) {
        WCHAR name[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, mods[i], name, MAX_PATH)) continue;
        WCHAR* base = wcsrchr(name, L'\\');
        if (!base) base = name; else base++;
        for (const WCHAR* legacy_name : legacy) {
            if (_wcsicmp(base, legacy_name) == 0) {
                MODULEINFO mi{};
                GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi));
                out->hModule  = mods[i];
                out->baseAddr = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
                out->size     = mi.SizeOfImage;
                if (hFile != INVALID_HANDLE_VALUE) {
                    const char tag[] = "MATCH (legacy): ";
                    DWORD w = 0; WriteFile(hFile, tag, sizeof(tag)-1, &w, nullptr);
                    dump_line_utf8(hFile, name);
                    CloseHandle(hFile);
                }
                return true;
            }
        }
    }

    if (hFile != INVALID_HANDLE_VALUE) {
        const char nomatch[] = "NO MATCH\r\n";
        DWORD w = 0; WriteFile(hFile, nomatch, sizeof(nomatch)-1, &w, nullptr);
        CloseHandle(hFile);
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════
//  ResolveGetNativeHandler — PE export parse for
//    ?GetNativeHandler@scrEngine@rage@@SAP6AXPEAVscrNativeCallContext@2@@Z_K@Z
// ═══════════════════════════════════════════════════════════════
uintptr_t ResolveGetNativeHandler(HANDLE hProcess, const LuaDllInfo& dll) {
    char dmsg[256];
    snprintf(dmsg, sizeof(dmsg),
             "ResolveGetNativeHandler enter — base=0x%llX size=%u",
             (unsigned long long)dll.baseAddr, (unsigned)dll.size);
    dbg_log(dmsg);

    IMAGE_DOS_HEADER dos{};
    if (!ReadProcessMemory(hProcess, (LPCVOID)dll.baseAddr, &dos, sizeof(dos), nullptr)) {
        dbg_log("ResolveGetNativeHandler: RPM dos failed"); return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) { dbg_log("bad DOS magic"); return 0; }

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadProcessMemory(hProcess, (LPCVOID)(dll.baseAddr + dos.e_lfanew),
                           &nt, sizeof(nt), nullptr)) {
        dbg_log("RPM nt failed"); return 0;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0) return 0;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!ReadProcessMemory(hProcess, (LPCVOID)(dll.baseAddr + expDir.VirtualAddress),
                           &exp, sizeof(exp), nullptr)) return 0;

    DWORD numNames = exp.NumberOfNames;
    if (numNames == 0) return 0;

    auto* nameRVAs = new DWORD[numNames];
    auto* funcRVAs = new DWORD[exp.NumberOfFunctions];
    auto* ordinals = new WORD[numNames];

    ReadProcessMemory(hProcess, (LPCVOID)(dll.baseAddr + exp.AddressOfNames),
                      nameRVAs, numNames * sizeof(DWORD), nullptr);
    ReadProcessMemory(hProcess, (LPCVOID)(dll.baseAddr + exp.AddressOfFunctions),
                      funcRVAs, exp.NumberOfFunctions * sizeof(DWORD), nullptr);
    ReadProcessMemory(hProcess, (LPCVOID)(dll.baseAddr + exp.AddressOfNameOrdinals),
                      ordinals, numNames * sizeof(WORD), nullptr);

    // Primary target: GetNativeHandler by hash (returns raw fn ptr)
    // Fallbacks: luaL_loadstring (if a legacy lua DLL got matched)
    const char* targets[] = {
        "?GetNativeHandler@scrEngine@rage@@SAP6AXPEAVscrNativeCallContext@2@@Z_K@Z",
        "luaL_dostring",
        "luaL_loadstring"
    };
    uintptr_t result = 0;
    const char* resolved = nullptr;
    for (const char* target : targets) {
        for (DWORD i = 0; i < numNames; i++) {
            char funcName[192]{};
            ReadProcessMemory(hProcess, (LPCVOID)(dll.baseAddr + nameRVAs[i]),
                              funcName, sizeof(funcName) - 1, nullptr);
            if (strcmp(funcName, target) == 0) {
                WORD ord = ordinals[i];
                result = dll.baseAddr + funcRVAs[ord];
                resolved = target;
                break;
            }
        }
        if (result) break;
    }

    delete[] nameRVAs;
    delete[] funcRVAs;
    delete[] ordinals;

    char rmsg[384];
    snprintf(rmsg, sizeof(rmsg), "ResolveGetNativeHandler result=0x%llX resolved=%s",
             (unsigned long long)result, resolved ? resolved : "NONE");
    dbg_log(rmsg);

    if (!result) {
        dbg_log("Resolver: triggering DumpAllCandidateExports");
        DumpAllCandidateExports(hProcess);
    }
    return result;
}

// v38 compat alias — startup validation thread calls this name
uintptr_t ResolveLuaDostring(HANDLE hProcess, const LuaDllInfo& dll) {
    return ResolveGetNativeHandler(hProcess, dll);
}

// v38: FindLuaState no longer needed. Return dll.baseAddr as sentinel.
uintptr_t FindLuaState(HANDLE hProcess, const LuaDllInfo& dll) {
    (void)hProcess;
    return dll.baseAddr;
}

// ═══════════════════════════════════════════════════════════════
//  Dump exports for every candidate scripting DLL (unchanged from v37)
// ═══════════════════════════════════════════════════════════════
static DWORD DumpDllExports(HANDLE hProcess, uintptr_t base, HANDLE hFile) {
    IMAGE_DOS_HEADER dos{};
    if (!ReadProcessMemory(hProcess, (LPCVOID)base, &dos, sizeof(dos), nullptr)) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadProcessMemory(hProcess, (LPCVOID)(base + dos.e_lfanew),
                           &nt, sizeof(nt), nullptr)) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;
    auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0) return 0;
    IMAGE_EXPORT_DIRECTORY exp{};
    if (!ReadProcessMemory(hProcess, (LPCVOID)(base + expDir.VirtualAddress),
                           &exp, sizeof(exp), nullptr)) return 0;
    if (exp.NumberOfNames == 0) return 0;
    auto* nameRVAs = new DWORD[exp.NumberOfNames];
    ReadProcessMemory(hProcess, (LPCVOID)(base + exp.AddressOfNames),
                      nameRVAs, exp.NumberOfNames * sizeof(DWORD), nullptr);
    DWORD w = 0;
    for (DWORD i = 0; i < exp.NumberOfNames; i++) {
        char funcName[256]{};
        ReadProcessMemory(hProcess, (LPCVOID)(base + nameRVAs[i]),
                          funcName, sizeof(funcName) - 1, nullptr);
        size_t len = strnlen(funcName, sizeof(funcName) - 1);
        if (len == 0) continue;
        if (len + 2 < sizeof(funcName)) {
            funcName[len]     = '\r';
            funcName[len + 1] = '\n';
            WriteFile(hFile, funcName, (DWORD)(len + 2), &w, nullptr);
        }
    }
    delete[] nameRVAs;
    return exp.NumberOfNames;
}

void DumpAllCandidateExports(HANDLE hProcess) {
    HMODULE mods[1024]; DWORD needed = 0;
    if (!EnumProcessModulesEx(hProcess, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) return;
    }
    DWORD count = needed / sizeof(HMODULE);
    WCHAR dumpPath[MAX_PATH];
    DWORD tn = GetEnvironmentVariableW(L"TEMP", dumpPath, MAX_PATH);
    if (tn == 0 || tn >= MAX_PATH - 32) return;
    wcscat_s(dumpPath, MAX_PATH, L"\\fivem_exports.txt");
    HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    const char intro[] =
        "FiveMMenu v38 - Dump de exports de DLLs candidatos\r\n"
        "Primario: rage-scripting-five.dll (GetNativeHandler by hash)\r\n\r\n";
    DWORD w = 0; WriteFile(hFile, intro, sizeof(intro) - 1, &w, nullptr);
    const WCHAR* targets[] = {
        L"rage-scripting-five.dll",
        L"scripting-gta.dll",
        L"citizen-scripting-core.dll",
        L"citizen-scripting-lua.dll"
    };
    for (DWORD i = 0; i < count; i++) {
        WCHAR name[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, mods[i], name, MAX_PATH)) continue;
        WCHAR* base = wcsrchr(name, L'\\');
        if (!base) base = name; else base++;
        bool interesting = w_contains_ci(base, L"lua") ||
                           w_contains_ci(base, L"scripting") ||
                           w_contains_ci(base, L"rage-");
        if (!interesting) {
            for (const WCHAR* t : targets) {
                if (_wcsicmp(base, t) == 0) { interesting = true; break; }
            }
        }
        if (!interesting) continue;
        MODULEINFO mi{};
        GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi));
        uintptr_t modBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        char header[512];
        int bl = WideCharToMultiByte(CP_UTF8, 0, base, -1, header, sizeof(header), nullptr, nullptr);
        if (bl <= 0) continue;
        char section[1024];
        int sl = snprintf(section, sizeof(section),
            "\r\n===== DLL: %s =====\r\nbase=0x%016llX size=%u\r\n--- exports ---\r\n",
            header, (unsigned long long)modBase, (unsigned)mi.SizeOfImage);
        WriteFile(hFile, section, sl, &w, nullptr);
        DWORD n = DumpDllExports(hProcess, modBase, hFile);
        char tail[64];
        int tl = snprintf(tail, sizeof(tail), "--- total: %lu exports ---\r\n",
                          (unsigned long)n);
        WriteFile(hFile, tail, tl, &w, nullptr);
    }
    CloseHandle(hFile);
}

// ═══════════════════════════════════════════════════════════════
//  FindAlertableThread — rotates across calls (v37, unchanged)
// ═══════════════════════════════════════════════════════════════
HANDLE FindAlertableThread(DWORD pid) {
    static DWORD s_lastTid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    struct Candidate { HANDLE h; DWORD tid; };
    const size_t MAX_C = 64;
    Candidate hi[MAX_C];   size_t hiN = 0;
    Candidate any_[MAX_C]; size_t anyN = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hThread = OpenThread(
                THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                FALSE, te.th32ThreadID);
            if (!hThread) continue;
            int prio = GetThreadPriority(hThread);
            if (prio >= 8 && prio <= 9) {
                if (hiN < MAX_C) hi[hiN++] = { hThread, te.th32ThreadID };
                else             CloseHandle(hThread);
            } else {
                if (anyN < MAX_C) any_[anyN++] = { hThread, te.th32ThreadID };
                else              CloseHandle(hThread);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    HANDLE chosen = nullptr;
    DWORD  chosenTid = 0;
    auto pick = [&](Candidate* arr, size_t n) {
        if (chosen || n == 0) return;
        for (size_t i = 0; i < n; i++) {
            if (arr[i].tid != s_lastTid) {
                chosen = arr[i].h; chosenTid = arr[i].tid;
                arr[i].h = nullptr; return;
            }
        }
        chosen = arr[0].h; chosenTid = arr[0].tid; arr[0].h = nullptr;
    };
    pick(hi, hiN);
    pick(any_, anyN);
    for (size_t i = 0; i < hiN;  i++) if (hi[i].h)   CloseHandle(hi[i].h);
    for (size_t i = 0; i < anyN; i++) if (any_[i].h) CloseHandle(any_[i].h);
    if (chosen) s_lastTid = chosenTid;
    return chosen;
}

// ═══════════════════════════════════════════════════════════════
//  ExecuteNative — v38 primary pipeline
//    Build native params + payload, split W^X alloc, APC, poll, free.
// ═══════════════════════════════════════════════════════════════
ExecResult ExecuteNative(HANDLE hProcess,
                         DWORD  pid,
                         uint64_t nativeHash,
                         const uint64_t* argv,
                         int numArgs,
                         uint64_t* resultOut)
{
    char d[256];
    snprintf(d, sizeof(d), "ExecuteNative hash=0x%llX nargs=%d",
             (unsigned long long)nativeHash, numArgs);
    dbg_log(d);

    if (numArgs < 0 || numArgs > 16) return ExecResult::LuaError;

    LuaDllInfo luaDll{};
    if (!FindLuaDll(hProcess, &luaDll))
        return ExecResult::LuaDllNotFound;

    uintptr_t pGetNative = ResolveGetNativeHandler(hProcess, luaDll);
    if (!pGetNative) {
        DumpAllCandidateExports(hProcess);
        return ExecResult::DostringNotFound;
    }

    HANDLE hThread = FindAlertableThread(pid);
    if (!hThread)
        return ExecResult::AlertableThreadNotFound;

    PayloadInfo payload = BuildPayload();

    // Split W^X allocation
    size_t paramsPadding  = (GetTickCount() % 2048) + 64;
    size_t paramsRegionSz = sizeof(ShellcodeParams) + paramsPadding;
    size_t payloadPadding  = (GetTickCount() % 2048) + 64;
    size_t payloadRegionSz = payload.size + payloadPadding;

    LPVOID regionA = VirtualAllocEx(hProcess, nullptr, paramsRegionSz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!regionA) { delete[] payload.data; CloseHandle(hThread); return ExecResult::ParamsAllocFailed; }

    LPVOID regionB = VirtualAllocEx(hProcess, nullptr, payloadRegionSz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!regionB) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        delete[] payload.data; CloseHandle(hThread);
        return ExecResult::PayloadAllocFailed;
    }

    // Noise-fill both regions
    auto* noiseA = new uint8_t[paramsRegionSz];
    auto* noiseB = new uint8_t[payloadRegionSz];
    for (size_t i = 0; i < paramsRegionSz; i++)
        noiseA[i] = static_cast<uint8_t>(__rdtsc() ^ (i * 0x5DEECE66DULL));
    for (size_t i = 0; i < payloadRegionSz; i++)
        noiseB[i] = static_cast<uint8_t>(__rdtsc() ^ (i * 0x5DEECE66DULL) ^ 0xA5);
    WriteProcessMemory(hProcess, regionA, noiseA, paramsRegionSz, nullptr);
    WriteProcessMemory(hProcess, regionB, noiseB, payloadRegionSz, nullptr);
    delete[] noiseA; delete[] noiseB;

    // Build params
    ShellcodeParams params{};
    params.pfnGetNativeHandler = pGetNative;
    params.nativeHash          = nativeHash;
    params.numArgs             = static_cast<uint32_t>(numArgs);
    params.executed            = 0;
    for (int i = 0; i < numArgs; i++)
        params.args[i] = argv[i];

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, regionA, &params, sizeof(params), &written)) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);
        delete[] payload.data; CloseHandle(hThread);
        return ExecResult::WriteFailed;
    }
    if (!WriteProcessMemory(hProcess, regionB, payload.data, payload.size, &written)) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);
        delete[] payload.data; CloseHandle(hThread);
        return ExecResult::WriteFailed;
    }

    auto ntQueueApc = reinterpret_cast<pfnNtQueueApcThread>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThread"));
    if (!ntQueueApc) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);
        delete[] payload.data; CloseHandle(hThread);
        return ExecResult::ApcFailed;
    }
    NTSTATUS status = ntQueueApc(hThread, regionB, regionA, nullptr, nullptr);
    if (status != 0) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);
        delete[] payload.data; CloseHandle(hThread);
        return ExecResult::ApcFailed;
    }

    // Jitter 50-500ms (ETW burst-correlation break — carryover from v37)
    DWORD jitterMs = 50 + static_cast<DWORD>(__rdtsc() % 451);
    Sleep(jitterMs);

    ExecResult result = ExecResult::Timeout;
    for (int i = 0; i < 200; i++) {
        uint32_t exec = 0;
        ReadProcessMemory(hProcess,
            &(static_cast<ShellcodeParams*>(regionA)->executed),
            &exec, sizeof(exec), nullptr);
        if (exec != 0) {
            if (resultOut) {
                ReadProcessMemory(hProcess,
                    &(static_cast<ShellcodeParams*>(regionA)->result[0]),
                    resultOut, sizeof(uint64_t), nullptr);
            }
            result = ExecResult::OK;
            break;
        }
        Sleep(10);
    }

    // Zero + release
    auto* zeroA = new uint8_t[paramsRegionSz]();
    auto* zeroB = new uint8_t[payloadRegionSz]();
    WriteProcessMemory(hProcess, regionA, zeroA, paramsRegionSz, nullptr);
    WriteProcessMemory(hProcess, regionB, zeroB, payloadRegionSz, nullptr);
    delete[] zeroA; delete[] zeroB;
    VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);

    delete[] payload.data;
    CloseHandle(hThread);
    return result;
}

// Backward-compat wrappers — the loader's old call sites still work.
ExecResult Execute(const char* /*luaScript*/) {
    // v38: a bare Execute("string") is now a probe. We dispatch
    // PLAYER_PED_ID (0x6E31E993AB12CA6F) to confirm the pipeline is
    // reachable end-to-end on this build.
    DWORD pid = FindFiveMPid();
    if (pid == 0) return ExecResult::ProcessNotFound;
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return ExecResult::OpenProcessFailed;
    uint64_t probe_result = 0;
    ExecResult r = ExecuteNative(hProcess, pid,
                                 0x6E31E993AB12CA6FULL, nullptr, 0,
                                 &probe_result);
    CloseHandle(hProcess);
    return r;
}

ExecResult Execute(const std::string& luaScript) {
    return Execute(luaScript.c_str());
}

ExecResult ExecuteEx(HANDLE hProcess, DWORD pid, const char* /*luaScript*/) {
    uint64_t probe_result = 0;
    return ExecuteNative(hProcess, pid, 0x6E31E993AB12CA6FULL, nullptr, 0,
                         &probe_result);
}

// v38 public API — convenience wrapper that opens the process itself.
ExecResult InvokeNativeOnce(uint64_t nativeHash,
                            const uint64_t* args,
                            int numArgs,
                            uint64_t* result) {
    DWORD pid = FindFiveMPid();
    if (pid == 0) return ExecResult::ProcessNotFound;
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return ExecResult::OpenProcessFailed;
    ExecResult r = ExecuteNative(hProcess, pid, nativeHash, args, numArgs, result);
    CloseHandle(hProcess);
    return r;
}

// v38 primary API — caller holds the handle to avoid repeated OpenProcess
// in the per-feature loops. g_execMtx protects the pipeline.
static HANDLE  g_cachedHandle = nullptr;
static DWORD   g_cachedPid    = 0;
static CRITICAL_SECTION g_cs;
static bool    g_csInit = false;

static void ensure_cs() {
    if (!g_csInit) { InitializeCriticalSection(&g_cs); g_csInit = true; }
}

ExecResult InvokeNative(uint64_t nativeHash,
                        const uint64_t* args,
                        int numArgs,
                        uint64_t* result)
{
    ensure_cs();
    EnterCriticalSection(&g_cs);
    DWORD pid = FindFiveMPid();
    if (pid == 0) { LeaveCriticalSection(&g_cs); return ExecResult::ProcessNotFound; }
    if (pid != g_cachedPid || !g_cachedHandle) {
        if (g_cachedHandle) CloseHandle(g_cachedHandle);
        g_cachedHandle = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION, FALSE, pid);
        g_cachedPid = pid;
    }
    if (!g_cachedHandle) { LeaveCriticalSection(&g_cs); return ExecResult::OpenProcessFailed; }
    HANDLE h = g_cachedHandle;
    DWORD  p = g_cachedPid;
    LeaveCriticalSection(&g_cs);

    return ExecuteNative(h, p, nativeHash, args, numArgs, result);
}

} // namespace LuaExecutor
