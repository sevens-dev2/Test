// lua_exec.cpp — v37 Metamorphic Lua Executor (implementation)
//
// v36 → v37 changes:
//   1. BuildPayload: picks a decoder variant (A/B/C) with anti-repeat
//      selection (no two consecutive runs reuse the same variant).
//      Each variant has its own byte sequence and length; key bytes
//      live at the same offsets (2..9) in each template.
//   2. ExecuteEx now splits the remote allocation:
//        regionA = PAGE_READWRITE          (holds ShellcodeParams)
//        regionB = PAGE_EXECUTE_READWRITE  (holds [NOPs|decoder|encoded])
//      NtQueueApcThread APC-routine = regionB base, arg1 = regionA base.
//      The shellcode entry preserves the v34 ABI: rcx points at params
//      (now in regionA), writes executed=1 to [rcx+0x2020]. After the
//      flip, both regions are zeroed and freed.
//      Removes the single-RWX allocation signature from v36.
//   3. #ifdef V37_IOCOMPLETION_APC optional dispatch path (default off):
//      alternate APC delivery via NtAssociateWaitCompletionPacket +
//      NtSubmitIoCompletion. Documented tradeoff retained.

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

// ═══════════════════════════════════════════════════════════════
//  v37: BuildPayload — metamorphic variant selection + 8-byte key
// ═══════════════════════════════════════════════════════════════
PayloadInfo BuildPayload() {
    PayloadInfo info{};

    // 1. 8-byte key (never all-zero) via xorshift64* over rdtsc / tick / addr / tid.
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

    // 2. Pick a decoder variant with anti-repeat.
    static int s_lastVariant = -1;
    int pick = static_cast<int>((__rdtsc() >> 3) % kDecoderVariantCount);
    if (pick == s_lastVariant) pick = (pick + 1) % kDecoderVariantCount;
    s_lastVariant = pick;
    info.decoderVariant = pick;

    const uint8_t* variant     = GetDecoderVariant(pick);
    const size_t   variantSize = kDecoderVariantSizes[pick];

    // 3. NOP padding (0-3 bytes) — shifts the decoder entry point
    info.nopCount = static_cast<int>(GetTickCount() & 0x3);

    // 4. Allocate caller buffer
    info.size = static_cast<size_t>(info.nopCount) + variantSize + kShellcodePlainSize;
    info.data = new uint8_t[info.size];

    size_t pos = 0;

    // 5. NOP prefix
    for (int i = 0; i < info.nopCount; i++)
        info.data[pos++] = 0x90;

    // 6. Decoder template + patch 8 inline key bytes at offsets 2..9
    memcpy(info.data + pos, variant, variantSize);
    for (size_t i = 0; i < kXorKeyLength; i++)
        info.data[pos + kXorKeyOffset + i] = info.xorKey[i];
    pos += variantSize;

    // 7. Encode shellcode: encoded[i] = plain[i] ^ key[i % 8]
    for (size_t i = 0; i < kShellcodePlainSize; i++)
        info.data[pos++] = kShellcodePlain[i] ^ info.xorKey[i % kXorKeyLength];

    return info;
}

// ═══════════════════════════════════════════════════════════════
//  FindFiveMPid — process snapshot
//
//  v37: broad match. FiveM moderno usa nomes versionados por build:
//    FiveM_GTAProcess.exe       (versao antiga sem build no nome)
//    FiveM_b2060_GTAProcess.exe (versoes b2060+ carregam build no nome)
//    FiveM_b2545_GTAProcess.exe
//    FiveM_b3407_GTAProcess.exe
//    ...
//    FiveM_Diag_GTAProcess.exe  (variante de diagnostico)
//    GTA5.exe                    (singleplayer / standalone)
//
//  Match: comeca com "FiveM" (case-insensitive) E contem "GTAProcess",
//  ou e exatamente "GTA5.exe". Pula "FiveM.exe" (launcher) e
//  "FiveMLauncher.exe".
// ═══════════════════════════════════════════════════════════════
static bool IsFiveMGameProcessName(const wchar_t* name) {
    if (!name) return false;
    if (_wcsicmp(name, L"GTA5.exe") == 0) return true;
    // Must start with FiveM (case-insensitive)
    if (_wcsnicmp(name, L"FiveM", 5) != 0) return false;
    // Must contain "GTAProcess" (case-insensitive) — exclui launcher
    const size_t len = wcslen(name);
    for (size_t i = 0; i + 10 <= len; i++) {
        if (_wcsnicmp(name + i, L"GTAProcess", 10) == 0) return true;
    }
    return false;
}

DWORD FindFiveMPid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

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
//  FindLuaDll — citizen-scripting-lua54.dll / lua54.dll (unchanged)
// ═══════════════════════════════════════════════════════════════
// Case-insensitive substring search in wide string
static bool w_contains_ci(const WCHAR* hay, const WCHAR* needle) {
    if (!hay || !needle) return false;
    size_t nlen = wcslen(needle);
    if (nlen == 0) return true;
    for (size_t i = 0; hay[i]; i++) {
        if (_wcsnicmp(hay + i, needle, nlen) == 0) return true;
    }
    return false;
}

bool FindLuaDll(HANDLE hProcess, LuaDllInfo* out) {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProcess, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        // Fallback: try without LIST_MODULES_ALL (older behaviour / bitness mismatch)
        if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
            return false;
    }

    DWORD count = needed / sizeof(HMODULE);

    // Pass 1: exact name match (fastest, matches v34/known builds)
    for (DWORD i = 0; i < count; i++) {
        WCHAR name[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, mods[i], name, MAX_PATH)) continue;
        WCHAR* base = wcsrchr(name, L'\\');
        if (!base) base = name; else base++;

        if (_wcsicmp(base, L"citizen-scripting-lua54.dll") == 0 ||
            _wcsicmp(base, L"lua54.dll") == 0) {
            MODULEINFO mi{};
            GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi));
            out->hModule  = mods[i];
            out->baseAddr = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            out->size     = mi.SizeOfImage;
            return true;
        }
    }

    // Pass 2: fuzzy match — any DLL whose BASENAME contains "lua54" or
    // "scripting-lua" (covers builds where the DLL was renamed, e.g.
    // "citizen-scripting-lua54-v2.dll", "scripting-lua54.dll", etc.)
    for (DWORD i = 0; i < count; i++) {
        WCHAR name[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, mods[i], name, MAX_PATH)) continue;
        WCHAR* base = wcsrchr(name, L'\\');
        if (!base) base = name; else base++;

        if (w_contains_ci(base, L"lua54") ||
            w_contains_ci(base, L"scripting-lua")) {
            MODULEINFO mi{};
            GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi));
            out->hModule  = mods[i];
            out->baseAddr = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            out->size     = mi.SizeOfImage;
            return true;
        }
    }

    // Nothing matched — dump the module list to %TEMP%\fivem_modules.txt
    // so the user can send us the DLL name their build is actually using.
    WCHAR dumpPath[MAX_PATH];
    DWORD tn = GetEnvironmentVariableW(L"TEMP", dumpPath, MAX_PATH);
    if (tn > 0 && tn < MAX_PATH - 32) {
        wcscat_s(dumpPath, MAX_PATH, L"\\fivem_modules.txt");
        HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            char header[128];
            int hl = snprintf(header, sizeof(header),
                "FiveMMenu v37 FindLuaDll — nenhum DLL de Lua localizado.\r\n"
                "Modulos enumerados no processo FiveM (%lu total):\r\n\r\n", count);
            DWORD w = 0;
            WriteFile(hFile, header, hl, &w, nullptr);

            for (DWORD i = 0; i < count && i < 500; i++) {
                WCHAR name[MAX_PATH];
                if (!GetModuleFileNameExW(hProcess, mods[i], name, MAX_PATH)) continue;
                char buf[MAX_PATH * 2];
                int bl = WideCharToMultiByte(CP_UTF8, 0, name, -1, buf, sizeof(buf) - 2, nullptr, nullptr);
                if (bl > 0) {
                    buf[bl - 1] = '\r';
                    buf[bl]     = '\n';
                    WriteFile(hFile, buf, bl + 1, &w, nullptr);
                }
            }
            CloseHandle(hFile);
        }
    }

    return false;
}

// ═══════════════════════════════════════════════════════════════
//  ResolveLuaDostring — remote PE parse (unchanged from v36)
// ═══════════════════════════════════════════════════════════════
uintptr_t ResolveLuaDostring(HANDLE hProcess, const LuaDllInfo& dll) {
    IMAGE_DOS_HEADER dos{};
    if (!ReadProcessMemory(hProcess, (LPCVOID)dll.baseAddr, &dos, sizeof(dos), nullptr))
        return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt{};
    uintptr_t ntAddr = dll.baseAddr + dos.e_lfanew;
    if (!ReadProcessMemory(hProcess, (LPCVOID)ntAddr, &nt, sizeof(nt), nullptr))
        return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0) return 0;

    uintptr_t expBase = dll.baseAddr + expDir.VirtualAddress;
    IMAGE_EXPORT_DIRECTORY exp{};
    if (!ReadProcessMemory(hProcess, (LPCVOID)expBase, &exp, sizeof(exp), nullptr))
        return 0;

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

    // v37: expanded target list. luaL_dostring is a MACRO in Lua 5.4
    // (`loadstring || pcall`), so it's never exported. We try several
    // candidates in priority order and take the first one found.
    //
    // Priority rationale:
    //   luaL_dostring   — some custom builds export it as a function
    //   luaL_loadstring — exists on vanilla Lua 5.4; needs lua_pcall after
    //                     (shellcode currently expects a one-shot dostring;
    //                      if only loadstring is found, user needs the
    //                      "loadstring+pcall" shellcode variant — ping
    //                      the author with the exports dump)
    //   lua_pcall / lua_pcallk — fundamental, always exported
    //   luaL_newstate  — proves the symbol table is readable
    const char* targets[] = {
        "luaL_dostring",
        "luaL_loadstring",
        "luaL_loadstringex",
        "luaL_loadbufferx",
        "luaL_loadbuffer",
        "luaL_loadfilex",
        "luaL_dofile"
    };
    uintptr_t result = 0;
    const char* resolved_name = nullptr;

    for (const char* target : targets) {
        for (DWORD i = 0; i < numNames; i++) {
            char funcName[64]{};
            ReadProcessMemory(hProcess, (LPCVOID)(dll.baseAddr + nameRVAs[i]),
                              funcName, sizeof(funcName) - 1, nullptr);
            if (strcmp(funcName, target) == 0) {
                WORD ord = ordinals[i];
                result = dll.baseAddr + funcRVAs[ord];
                resolved_name = target;
                break;
            }
        }
        if (result) break;
    }

    // v37 debug: dump the full export list to %TEMP%\fivem_exports.txt
    // on every call so the user can inspect what their build actually
    // exports (useful when ResolveLuaDostring returns 0 because the
    // mainline target names were renamed/stripped).
    WCHAR dumpPath[MAX_PATH];
    DWORD tn = GetEnvironmentVariableW(L"TEMP", dumpPath, MAX_PATH);
    if (tn > 0 && tn < MAX_PATH - 32) {
        wcscat_s(dumpPath, MAX_PATH, L"\\fivem_exports.txt");
        HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            char header[256];
            int hl = snprintf(header, sizeof(header),
                "FiveMMenu v37 ResolveLuaDostring — exports do DLL de Lua\r\n"
                "DLL base=0x%016llX size=%u\r\n"
                "Exports totais: %lu\r\n"
                "Resolvido: %s (@ 0x%016llX)\r\n\r\n",
                (unsigned long long)dll.baseAddr, (unsigned)dll.size,
                (unsigned long)numNames,
                resolved_name ? resolved_name : "NENHUM",
                (unsigned long long)result);
            DWORD w = 0;
            WriteFile(hFile, header, hl, &w, nullptr);
            for (DWORD i = 0; i < numNames; i++) {
                char funcName[128]{};
                ReadProcessMemory(hProcess, (LPCVOID)(dll.baseAddr + nameRVAs[i]),
                                  funcName, sizeof(funcName) - 1, nullptr);
                size_t len = strnlen(funcName, sizeof(funcName) - 1);
                if (len == 0) continue;
                funcName[len] = '\r';
                if (len + 2 < sizeof(funcName)) {
                    funcName[len + 1] = '\n';
                    WriteFile(hFile, funcName, (DWORD)(len + 2), &w, nullptr);
                }
            }
            CloseHandle(hFile);
        }
    }

    delete[] nameRVAs;
    delete[] funcRVAs;
    delete[] ordinals;
    return result;
}

// ═══════════════════════════════════════════════════════════════
//  FindLuaState — unchanged from v36 (budget, cache, 256KB blocks)
// ═══════════════════════════════════════════════════════════════
uintptr_t FindLuaState(HANDLE hProcess, const LuaDllInfo& dll) {
    struct CacheEntry { uintptr_t base; bool scanned; };
    static CacheEntry s_cache[1024];
    static size_t    s_cacheN = 0;

    auto wasScanned = [](uintptr_t base) -> bool {
        for (size_t i = 0; i < s_cacheN; i++)
            if (s_cache[i].base == base) return s_cache[i].scanned;
        return false;
    };
    auto markScanned = [](uintptr_t base) {
        for (size_t i = 0; i < s_cacheN; i++) {
            if (s_cache[i].base == base) { s_cache[i].scanned = true; return; }
        }
        if (s_cacheN < 1024) s_cache[s_cacheN++] = { base, true };
    };

    struct Region { uintptr_t base; size_t size; uint64_t dist; };
    const size_t MAX_R = 2048;
    Region regions[MAX_R];
    size_t rN = 0;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        bool isPrivate   = (mbi.Type == MEM_PRIVATE);
        bool isImage     = (mbi.Type == MEM_IMAGE);
        bool isCommitted = (mbi.State == MEM_COMMIT);
        bool isRW        = (mbi.Protect == PAGE_READWRITE);
        size_t regionSize = mbi.RegionSize;
        uintptr_t base    = reinterpret_cast<uintptr_t>(mbi.BaseAddress);

        if (isPrivate && !isImage && isCommitted && isRW &&
            regionSize >= 64 && regionSize <= 0x100000) {
            if (!wasScanned(base) && rN < MAX_R) {
                uint64_t dist = (base >= dll.baseAddr)
                    ? (base - dll.baseAddr)
                    : (dll.baseAddr - base);
                regions[rN++] = { base, regionSize, dist };
            }
        }

        addr = base + mbi.RegionSize;
        if (addr < base) break;
    }

    for (size_t i = 1; i < rN; i++) {
        Region tmp = regions[i];
        size_t j = i;
        while (j > 0 && regions[j - 1].dist > tmp.dist) {
            regions[j] = regions[j - 1];
            j--;
        }
        regions[j] = tmp;
    }

    int rpmBudget = 100;

    for (size_t ri = 0; ri < rN; ri++) {
        if (rpmBudget <= 0) break;

        Region& R = regions[ri];
        size_t blockSize = (R.size < 0x40000) ? R.size : 0x40000;
        auto* buf = new uint8_t[blockSize];

        bool hit = false;
        uintptr_t hitAddr = 0;
        bool completed = true;

        for (size_t blockOff = 0; blockOff < R.size; blockOff += blockSize) {
            if (rpmBudget <= 0) { completed = false; break; }

            size_t readSize = R.size - blockOff;
            if (readSize > blockSize) readSize = blockSize;

            SIZE_T bytesRead = 0;
            BOOL ok = ReadProcessMemory(hProcess,
                                        (LPCVOID)(R.base + blockOff),
                                        buf, readSize, &bytesRead);
            --rpmBudget;
            if (!ok || bytesRead < 32) continue;

            for (size_t i = 0; i + 32 <= bytesRead; i += 8) {
                uint8_t tt     = buf[i + 8];
                uint8_t marked = buf[i + 9];
                uint8_t status = buf[i + 10];

                if (tt != 0x28) continue;
                if (marked != 0x04 && marked != 0x08 && marked != 0x14) continue;
                if (status != 0x00) continue;

                uint64_t l_G = *reinterpret_cast<uint64_t*>(&buf[i + 0x10]);
                uint64_t ci  = *reinterpret_cast<uint64_t*>(&buf[i + 0x18]);
                if (l_G < 0x10000 || ci < 0x10000) continue;

                if (rpmBudget <= 0) { completed = false; break; }

                MEMORY_BASIC_INFORMATION check{};
                if (VirtualQueryEx(hProcess, (LPCVOID)l_G, &check, sizeof(check)) == sizeof(check)) {
                    if (check.State == MEM_COMMIT) {
                        hit = true;
                        hitAddr = R.base + blockOff + i;
                        break;
                    }
                }
            }
            if (hit) break;
        }
        delete[] buf;

        if (hit) return hitAddr;
        if (completed) markScanned(R.base);
    }

    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  FindAlertableThread — unchanged from v36 (rotation across calls)
// ═══════════════════════════════════════════════════════════════
HANDLE FindAlertableThread(DWORD pid) {
    static DWORD s_lastTid = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

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
                chosen    = arr[i].h;
                chosenTid = arr[i].tid;
                arr[i].h  = nullptr;
                return;
            }
        }
        chosen    = arr[0].h;
        chosenTid = arr[0].tid;
        arr[0].h  = nullptr;
    };

    pick(hi, hiN);
    pick(any_, anyN);

    for (size_t i = 0; i < hiN;  i++) if (hi[i].h)   CloseHandle(hi[i].h);
    for (size_t i = 0; i < anyN; i++) if (any_[i].h) CloseHandle(any_[i].h);

    if (chosen) s_lastTid = chosenTid;
    return chosen;
}

// ═══════════════════════════════════════════════════════════════
//  Execute — full pipeline (unchanged outer shape)
// ═══════════════════════════════════════════════════════════════
ExecResult Execute(const char* luaScript) {
    DWORD pid = FindFiveMPid();
    if (pid == 0) return ExecResult::ProcessNotFound;

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProcess) return ExecResult::OpenProcessFailed;

    ExecResult r = ExecuteEx(hProcess, pid, luaScript);
    CloseHandle(hProcess);
    return r;
}

// ═══════════════════════════════════════════════════════════════
//  v37 ExecuteEx — split W^X layout
//    regionA (PAGE_READWRITE)         : ShellcodeParams + padding
//    regionB (PAGE_EXECUTE_READWRITE) : NOPs + decoder + encoded
//  NtQueueApcThread(ApcRoutine=regionB_entry, ApcArgument1=regionA_base).
//  Shellcode's `mov rbx, rcx` lands rbx at regionA.
// ═══════════════════════════════════════════════════════════════
ExecResult ExecuteEx(HANDLE hProcess, DWORD pid, const char* luaScript) {
    LuaDllInfo luaDll{};
    if (!FindLuaDll(hProcess, &luaDll))
        return ExecResult::LuaDllNotFound;

    uintptr_t pDostring = ResolveLuaDostring(hProcess, luaDll);
    if (!pDostring)
        return ExecResult::DostringNotFound;

    uintptr_t pLuaState = FindLuaState(hProcess, luaDll);
    if (!pLuaState)
        return ExecResult::LuaStateNotFound;

    HANDLE hThread = FindAlertableThread(pid);
    if (!hThread)
        return ExecResult::AlertableThreadNotFound;

    PayloadInfo payload = BuildPayload();

    // v37: split allocations.
    size_t paramsPadding  = (GetTickCount() % 2048) + 64;
    size_t paramsRegionSz = sizeof(ShellcodeParams) + paramsPadding;

    size_t payloadPadding  = (GetTickCount() % 2048) + 64;
    size_t payloadRegionSz = payload.size + payloadPadding;

    LPVOID regionA = VirtualAllocEx(hProcess, nullptr, paramsRegionSz,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
    if (!regionA) {
        delete[] payload.data;
        CloseHandle(hThread);
        return ExecResult::ParamsAllocFailed;
    }

    LPVOID regionB = VirtualAllocEx(hProcess, nullptr, payloadRegionSz,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!regionB) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        delete[] payload.data;
        CloseHandle(hThread);
        return ExecResult::PayloadAllocFailed;
    }

    // Noise fill both regions (defeats entropy heuristics)
    auto* noiseA = new uint8_t[paramsRegionSz];
    auto* noiseB = new uint8_t[payloadRegionSz];
    for (size_t i = 0; i < paramsRegionSz; i++)
        noiseA[i] = static_cast<uint8_t>(__rdtsc() ^ (i * 0x5DEECE66DULL));
    for (size_t i = 0; i < payloadRegionSz; i++)
        noiseB[i] = static_cast<uint8_t>(__rdtsc() ^ (i * 0x5DEECE66DULL) ^ 0xA5);
    WriteProcessMemory(hProcess, regionA, noiseA, paramsRegionSz, nullptr);
    WriteProcessMemory(hProcess, regionB, noiseB, payloadRegionSz, nullptr);
    delete[] noiseA;
    delete[] noiseB;

    // Build params into regionA
    ShellcodeParams params{};
    params.pfnLuaLDostring = pDostring;
    params.pLuaState       = pLuaState;
    params.pfnVirtualFree  = 0;
    params.pSelf           = reinterpret_cast<uint64_t>(regionB);
    params.executed        = 0;
    params.luaError        = 0;

    size_t scriptLen = strlen(luaScript);
    if (scriptLen >= sizeof(params.script))
        scriptLen = sizeof(params.script) - 1;
    memcpy(params.script, luaScript, scriptLen);
    params.script[scriptLen] = '\0';

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, regionA, &params, sizeof(params), &written)) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);
        delete[] payload.data;
        CloseHandle(hThread);
        return ExecResult::WriteFailed;
    }

    if (!WriteProcessMemory(hProcess, regionB, payload.data, payload.size, &written)) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);
        delete[] payload.data;
        CloseHandle(hThread);
        return ExecResult::WriteFailed;
    }

    auto ntQueueApc = reinterpret_cast<pfnNtQueueApcThread>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThread"));
    if (!ntQueueApc) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);
        delete[] payload.data;
        CloseHandle(hThread);
        return ExecResult::ApcFailed;
    }

    // ApcRoutine = regionB (payload entry); arg1 = regionA (params for rcx)
    NTSTATUS status = ntQueueApc(hThread, regionB, regionA, nullptr, nullptr);
    if (status != 0) {
        VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);
        delete[] payload.data;
        CloseHandle(hThread);
        return ExecResult::ApcFailed;
    }

    // v36 jitter preserved
    DWORD jitterMs = 50 + static_cast<DWORD>(__rdtsc() % 451);
    Sleep(jitterMs);

    ExecResult result = ExecResult::Timeout;
    for (int i = 0; i < 200; i++) {
        uint32_t executed = 0;
        ReadProcessMemory(hProcess,
            &(static_cast<ShellcodeParams*>(regionA)->executed),
            &executed, sizeof(executed), nullptr);

        if (executed != 0) {
            uint32_t luaErr = 0;
            ReadProcessMemory(hProcess,
                &(static_cast<ShellcodeParams*>(regionA)->luaError),
                &luaErr, sizeof(luaErr), nullptr);
            result = (luaErr == 0) ? ExecResult::OK : ExecResult::LuaError;
            break;
        }
        Sleep(10);
    }

    // Zero + release both regions
    auto* zeroA = new uint8_t[paramsRegionSz]();
    auto* zeroB = new uint8_t[payloadRegionSz]();
    WriteProcessMemory(hProcess, regionA, zeroA, paramsRegionSz, nullptr);
    WriteProcessMemory(hProcess, regionB, zeroB, payloadRegionSz, nullptr);
    delete[] zeroA;
    delete[] zeroB;
    VirtualFreeEx(hProcess, regionA, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, regionB, 0, MEM_RELEASE);

    delete[] payload.data;
    CloseHandle(hThread);
    return result;
}

#ifdef V37_IOCOMPLETION_APC
// ═══════════════════════════════════════════════════════════════
//  Alternate dispatch path (default-off): NtCreateIoCompletion +
//  NtSubmitIoCompletion. Trades ETW APC event for an IoCompletion
//  packet. Residual: still emits a KernelProcessCompletion event
//  type; different scanner-trigger surface. Documented, not wired.
// ═══════════════════════════════════════════════════════════════
ExecResult ExecuteEx_IoCompletionAlt(HANDLE, DWORD, const char*) {
    // Stub: real impl needs NtCreateIoCompletion, NtAssociateWaitCompletionPacket,
    // NtSubmitIoCompletion signatures from ntdll. Opt-in path only.
    return ExecResult::ApcFailed;
}
#endif // V37_IOCOMPLETION_APC

} // namespace LuaExecutor
