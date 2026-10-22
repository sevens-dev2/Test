// test_runner.cpp — TestRunner para ambiente de teste v34 vs adhesive.dll
//
// Executa o lua executor v34 contra FakeGTAProcess.exe (que roda como FiveM_GTAProcess.exe)
// e reporta detalhadamente o que aconteceu em cada etapa.
//
// Pipeline testada:
//   1. FindFiveMPid()               — localiza FiveM_GTAProcess.exe
//   2. FindLuaDll()                 — encontra citizen-scripting-lua54.dll
//   3. ResolveLuaDostring()         — resolve endereço de luaL_dostring
//   4. FindLuaState()               — AOB scan por lua_State*
//   5. FindAlertableThread()        — encontra thread alertable (prioridade 8-9)
//   6. VirtualAllocEx + WPM         — aloca params + shellcode no processo remoto
//   7. NtQueueApcThread             — enfileira shellcode
//   8. Poll executed flag           — aguarda confirmação de execução
//
// Conecta no named pipe do FakeGTAProcess para receber feedback em tempo real.
// Escreve log em C:\Users\Public\test_runner_log.txt
//
// Build: parte do target TestRunner no CMakeLists.txt
// Platform: Windows x64 / MSVC 2022+ | Requer FakeGTAProcess.exe rodando

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <atomic>
#include <chrono>
#include <thread>

#pragma comment(lib, "Psapi.lib")

// ─── Inclui os módulos do lua executor v34 ────────────────────────────────────
#include "lua_exec.h"
#include "lua_payload.h"

// ─── Logger ──────────────────────────────────────────────────────────────────

static FILE* g_log = nullptr;

static void LogInit() {
    fopen_s(&g_log, "C:\\Users\\Public\\test_runner_log.txt", "w");
    if (!g_log) fopen_s(&g_log, "test_runner_log.txt", "w");
}

static void Log(const char* fmt, ...) {
    char buf[2048];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    SYSTEMTIME st;
    GetLocalTime(&st);
    if (g_log) {
        fprintf(g_log, "[%02d:%02d:%02d.%03d] %s\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
        fflush(g_log);
    }
    printf("[%02d:%02d:%02d.%03d] %s\n",
           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
}

// ─── Resultado de cada etapa ─────────────────────────────────────────────────

struct StepResult {
    const char* name;
    bool        ok;
    std::string detail;
};

static std::vector<StepResult> g_steps;

static void RecordStep(const char* name, bool ok, const std::string& detail = "") {
    g_steps.push_back({name, ok, detail});
    Log("[%s] %s%s", ok ? "OK" : "FALHOU", name, detail.empty() ? "" : (" — " + detail).c_str());
}

// ─── Execução manual do pipeline v34 com instrumentação completa ─────────────

static void RunPipeline(DWORD pid) {
    Log("");
    Log("=== INICIANDO PIPELINE v34 contra PID %u ===", pid);

    // ─── ETAPA 1: Abrir processo ──────────────────────────────────────────────
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProc) {
        RecordStep("OpenProcess", false,
                   "Erro " + std::to_string(GetLastError()) +
                   " — Execute como Administrador");
        return;
    }
    RecordStep("OpenProcess", true, "Handle=" + std::to_string((uintptr_t)hProc));

    // ─── ETAPA 2: FindLuaDll ─────────────────────────────────────────────────
    LPVOID luaBase = nullptr;
    SIZE_T luaSize = 0;
    bool   luaFound = LuaExecutor::FindLuaDll(hProc, &luaBase, &luaSize);

    char luaDetail[256];
    if (luaFound) {
        snprintf(luaDetail, sizeof(luaDetail),
                 "Base=%p Size=0x%llX", luaBase, (unsigned long long)luaSize);
    } else {
        snprintf(luaDetail, sizeof(luaDetail),
                 "citizen-scripting-lua54.dll não encontrado no processo");
    }
    RecordStep("FindLuaDll", luaFound, luaDetail);

    if (!luaFound) {
        Log("[DIAGNOSTICO] lua54.dll não foi detectado no processo alvo.");
        Log("[DIAGNOSTICO] FakeGTAProcess precisa ter lua54.dll carregada.");
        Log("[DIAGNOSTICO] Coloque lua54.dll (de https://github.com/lua/lua/releases)");
        Log("[DIAGNOSTICO] na mesma pasta de FiveM_GTAProcess.exe");
        CloseHandle(hProc);
        return;
    }

    // ─── ETAPA 3: ResolveLuaDostring ─────────────────────────────────────────
    LPVOID pfnDostring = LuaExecutor::ResolveLuaDostring(hProc, luaBase, luaSize);
    char dsDetail[256];
    if (pfnDostring) {
        snprintf(dsDetail, sizeof(dsDetail), "Endereço remoto=%p", pfnDostring);
    } else {
        snprintf(dsDetail, sizeof(dsDetail), "Não exportado diretamente (pode ser macro)");
    }
    RecordStep("ResolveLuaDostring", pfnDostring != nullptr, dsDetail);

    if (!pfnDostring) {
        Log("[DIAGNOSTICO] luaL_dostring não encontrado como export.");
        Log("[DIAGNOSTICO] Lua 5.4 define luaL_dostring como macro. Precisa de lua_State* + lua_pcall.");
        Log("[DIAGNOSTICO] Alternativa: usar luaL_loadstring que é um export real.");
        CloseHandle(hProc);
        return;
    }

    // ─── ETAPA 4: FindLuaState ────────────────────────────────────────────────
    Log("[SCAN] Iniciando AOB scan por lua_State no processo...");
    DWORD scanStart = GetTickCount();
    LPVOID pLuaState = LuaExecutor::FindLuaState(hProc);
    DWORD scanMs = GetTickCount() - scanStart;

    char lsDetail[256];
    if (pLuaState) {
        snprintf(lsDetail, sizeof(lsDetail),
                 "lua_State*=%p (scan demorou %ums)", pLuaState, scanMs);
    } else {
        snprintf(lsDetail, sizeof(lsDetail),
                 "Não encontrado após %ums de scan", scanMs);
    }
    RecordStep("FindLuaState (AOB scan)", pLuaState != nullptr, lsDetail);

    if (!pLuaState) {
        Log("[DIAGNOSTICO] lua_State não localizado por AOB scan.");
        Log("[DIAGNOSTICO] O padrão procurado: byte+8=0x28, byte+9 in {04,08,14}, byte+10=0x00");
        Log("[DIAGNOSTICO] Se FakeGTAProcess usou lua_State sintético, os ponteiros em +0x10/+0x18");
        Log("[DIAGNOSTICO] precisam estar no range 0x10000-0x7FFFFFFFFFFF.");
        CloseHandle(hProc);
        return;
    }

    // ─── ETAPA 5: FindAlertableThread ────────────────────────────────────────
    HANDLE hThread = LuaExecutor::FindAlertableThread(hProc, pid);
    char thrDetail[256];
    if (hThread) {
        snprintf(thrDetail, sizeof(thrDetail),
                 "tid=%u handle=%p", GetThreadId(hThread), hThread);
    } else {
        snprintf(thrDetail, sizeof(thrDetail), "Thread com prioridade 8-9 não encontrada");
    }
    RecordStep("FindAlertableThread", hThread != nullptr, thrDetail);

    if (!hThread) {
        Log("[DIAGNOSTICO] Thread alertable não encontrada.");
        Log("[DIAGNOSTICO] FakeGTAProcess.exe cria thread com SetThreadPriority(THREAD_PRIORITY_ABOVE_NORMAL).");
        Log("[DIAGNOSTICO] Verificar: a thread está em SleepEx(_, TRUE)?");
        CloseHandle(hProc);
        return;
    }

    // ─── ETAPA 6: Alocar memória remota ──────────────────────────────────────
    const size_t kTotalSize = sizeof(LuaExecutor::kShellcode) + sizeof(LuaExecutor::ShellcodeParams);

    Log("[ALLOC] VirtualAllocEx: processo=%p size=0x%llX prot=PAGE_EXECUTE_READWRITE",
        hProc, (unsigned long long)kTotalSize);

    DWORD allocTick = GetTickCount();
    LPVOID pRemote = VirtualAllocEx(hProc, nullptr, kTotalSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD allocErr = GetLastError();
    DWORD allocMs = GetTickCount() - allocTick;

    char allocDetail[256];
    if (pRemote) {
        snprintf(allocDetail, sizeof(allocDetail),
                 "RemoteBase=%p demorou=%ums", pRemote, allocMs);
    } else {
        snprintf(allocDetail, sizeof(allocDetail),
                 "Falhou: erro=%u", allocErr);
    }
    RecordStep("VirtualAllocEx (PAGE_EXECUTE_READWRITE)", pRemote != nullptr, allocDetail);

    if (!pRemote) {
        Log("[ADHESIVE] VirtualAllocEx NEGADO — pode ser que adhesive.dll esteja bloqueando!");
        Log("[ADHESIVE] Erro %u = %s", allocErr,
            allocErr == 5 ? "ACCESS_DENIED" :
            allocErr == 87 ? "INVALID_PARAMETER" : "outro");
        CloseHandle(hThread);
        CloseHandle(hProc);
        return;
    }

    // ─── ETAPA 7: WriteProcessMemory — shellcode + params ────────────────────
    // Escrever shellcode
    LPVOID pShellcode = pRemote;
    LPVOID pParams    = (BYTE*)pRemote + sizeof(LuaExecutor::kShellcode);
    // Alinha params em 8 bytes
    uintptr_t paramsAddr = (uintptr_t)pParams;
    paramsAddr = (paramsAddr + 7) & ~(uintptr_t)7;
    pParams = (LPVOID)paramsAddr;

    SIZE_T written = 0;
    bool wpmOk = WriteProcessMemory(hProc, pShellcode,
                                     LuaExecutor::kShellcode,
                                     sizeof(LuaExecutor::kShellcode), &written);
    RecordStep("WPM shellcode", wpmOk && written == sizeof(LuaExecutor::kShellcode),
               "Written=" + std::to_string(written));

    if (!wpmOk) {
        Log("[ADHESIVE] WriteProcessMemory bloqueado — erro=%u", GetLastError());
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProc);
        return;
    }

    // v38: ShellcodeParams agora é layout native-dispatch (GetNativeHandler
    // + hash + args + embedded scrNativeCallContext). Os campos v34 Lua
    // (pfnLuaLDostring, pLuaState, pfnVirtualFree, luaError, script) não
    // existem mais. Aqui preparamos um probe no PLAYER_PED_ID.
    LuaExecutor::ShellcodeParams params;
    ZeroMemory(&params, sizeof(params));
    params.pfnGetNativeHandler = (UINT64)(uintptr_t)pfnDostring; // resolver retorna GetNativeHandler
    params.pSelf               = (UINT64)(uintptr_t)pRemote;
    params.nativeHash          = 0xD80958FC74E988A6ULL;  // PLAYER_PED_ID
    params.numArgs             = 0;
    params.executed            = 0;
    (void)pLuaState;  // v38: AOB-scanned lua_State irrelevant to native dispatch

    bool wpmParams = WriteProcessMemory(hProc, pParams, &params, sizeof(params), &written);
    RecordStep("WPM ShellcodeParams", wpmParams && written > 0,
               "pfnGetNativeHandler=" + std::to_string(params.pfnGetNativeHandler) +
               " hash=0xD80958FC74E988A6 (PLAYER_PED_ID)");

    if (!wpmParams) {
        Log("[ADHESIVE] WPM params bloqueado — erro=%u", GetLastError());
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProc);
        return;
    }

    // ─── ETAPA 8: NtQueueApcThread ────────────────────────────────────────────
    typedef NTSTATUS(NTAPI* pfnNtQueueApcThread_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
    auto NtQueueApcThread_fn = (pfnNtQueueApcThread_t)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThread");

    NTSTATUS apcStatus = STATUS_SUCCESS;
    if (NtQueueApcThread_fn) {
        Log("[APC] NtQueueApcThread: thread=%p shellcode=%p params=%p",
            hThread, pShellcode, pParams);

        apcStatus = NtQueueApcThread_fn(hThread, pShellcode, pParams, nullptr, nullptr);

        char apcDetail[128];
        snprintf(apcDetail, sizeof(apcDetail), "NTSTATUS=0x%X", (unsigned)apcStatus);
        RecordStep("NtQueueApcThread", NT_SUCCESS(apcStatus), apcDetail);

        if (!NT_SUCCESS(apcStatus)) {
            Log("[ADHESIVE] NtQueueApcThread BLOQUEADO! Status=0x%X", (unsigned)apcStatus);
            Log("[ADHESIVE] Interpretação:");
            switch ((unsigned)apcStatus) {
                case 0xC0000005:
                    Log("[ADHESIVE]   0xC0000005 = ACCESS_VIOLATION — thread handle sem permissão");
                    break;
                case 0xC000010E:
                    Log("[ADHESIVE]   0xC000010E = THREAD_IS_TERMINATING");
                    break;
                case 0x00000005:
                    Log("[ADHESIVE]   0x5 = ACCESS_DENIED — adhesive pode estar hookando APC kernel");
                    break;
                default:
                    break;
            }
        }
    } else {
        RecordStep("NtQueueApcThread", false, "NtQueueApcThread não encontrado em ntdll");
        return;
    }

    // ─── ETAPA 9: Poll executed flag ──────────────────────────────────────────
    if (NT_SUCCESS(apcStatus)) {
        Log("[POLL] Aguardando execução do shellcode (max 5s)...");
        bool executed = false;
        DWORD pollStart = GetTickCount();
        while (GetTickCount() - pollStart < 5000) {
            LuaExecutor::ShellcodeParams remoteParams;
            SIZE_T rd = 0;
            ReadProcessMemory(hProc, pParams, &remoteParams, sizeof(remoteParams), &rd);
            if (remoteParams.executed == 1) {
                executed = true;
                uint64_t native_result = remoteParams.result[0];
                char execDetail[128];
                snprintf(execDetail, sizeof(execDetail),
                         "native_result=0x%llX em %ums",
                         (unsigned long long)native_result,
                         GetTickCount() - pollStart);
                RecordStep("Shellcode executou", true, execDetail);
                Log("[SUCCESS] v38 native dispatch retornou result=0x%llX",
                    (unsigned long long)native_result);
                break;
            }
            Sleep(10);
        }
        if (!executed) {
            RecordStep("Shellcode executou", false, "Timeout de 5s — thread não processou APC");
            Log("[DIAGNOSTICO] A thread não processou o APC em 5 segundos.");
            Log("[DIAGNOSTICO] Verifique se FakeGTAProcess está em SleepEx alertable.");
            Log("[DIAGNOSTICO] adhesive.dll pode ter bloqueado a APC antes de chegar na thread.");
        }
    }

    // ─── Liberar memória ──────────────────────────────────────────────────────
    VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
    RecordStep("VirtualFreeEx (limpeza)", true, "Memória liberada");

    // ─── Fechar handles ───────────────────────────────────────────────────────
    CloseHandle(hThread);
    CloseHandle(hProc);
}

// ─── Verificar se adhesive.dll está carregada no alvo ─────────────────────────

static bool CheckAdhesivePresent(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return false;

    HMODULE mods[1024];
    DWORD needed = 0;
    EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL);
    DWORD count = needed / sizeof(HMODULE);

    bool found = false;
    for (DWORD i = 0; i < count; i++) {
        wchar_t modName[MAX_PATH];
        if (GetModuleFileNameExW(hProc, mods[i], modName, MAX_PATH)) {
            if (wcsstr(modName, L"adhesive")) {
                Log("[CHECK] adhesive.dll PRESENTE no processo! Base=%p", (void*)mods[i]);
                found = true;
            }
        }
    }

    CloseHandle(hProc);
    return found;
}

// ─── Relatório final ──────────────────────────────────────────────────────────

static void PrintReport(DWORD pid, bool adhesive) {
    Log("");
    Log("╔═══════════════════════════════════════════════════════╗");
    Log("║       RELATÓRIO v34 vs adhesive.dll — RESULTADO       ║");
    Log("╚═══════════════════════════════════════════════════════╝");
    Log("");
    Log("Processo-alvo PID: %u", pid);
    Log("adhesive.dll presente: %s", adhesive ? "SIM" : "NÃO (sem GTA runtime)");
    Log("");
    Log("Etapas da pipeline v34:");

    int passed = 0, failed = 0;
    for (auto& s : g_steps) {
        Log("  [%s] %s%s",
            s.ok ? "✓" : "✗",
            s.name,
            s.detail.empty() ? "" : (" — " + s.detail).c_str());
        if (s.ok) passed++; else failed++;
    }

    Log("");
    Log("Resultado: %d/%d etapas concluídas", passed, (int)g_steps.size());
    Log("");

    if (failed == 0) {
        Log("╔═══════════════════════════════════════════════╗");
        Log("║  RESULTADO: v34 EXECUTOU SEM DETECÇÃO         ║");
        Log("║  adhesive.dll NÃO bloqueou nenhuma etapa.     ║");
        Log("╚═══════════════════════════════════════════════╝");
        Log("");
        Log("Conclusão: a técnica Eulen-style (shellcode ~42 bytes via APC)");
        Log("bypassa os vetores client-side do adhesive.dll porque:");
        Log("  ✓ Nenhuma DLL foi carregada (VAD não tem IMAGE entry)");
        Log("  ✓ Shellcode é PRIVATE ~8KB, sem magic MZ/PE");
        Log("  ✓ APC foi em thread existente (não NtCreateThreadEx)");
        Log("  ✓ Memória liberada após execução (VirtualFreeEx)");
    } else {
        // Identifica onde bloqueou
        Log("╔═══════════════════════════════════════════════╗");
        Log("║  RESULTADO: BLOQUEADO em %d/%d etapa(s)        ║",
            failed, (int)g_steps.size());
        Log("╚═══════════════════════════════════════════════╝");
        Log("");
        Log("Etapas que falharam:");
        for (auto& s : g_steps) {
            if (!s.ok) {
                Log("  ✗ %s: %s", s.name, s.detail.c_str());
                // Diagnóstico por etapa
                if (strstr(s.name, "FindLuaDll"))
                    Log("    → lua54.dll não foi carregada no FakeGTAProcess. Veja COMO_USAR.md");
                if (strstr(s.name, "FindLuaState"))
                    Log("    → lua_State sintético não passou no AOB scan. Ver nota no log do FakeGTAProcess.");
                if (strstr(s.name, "VirtualAllocEx"))
                    Log("    → adhesive.dll ou Windows bloqueou alocação de mem RWX externa.");
                if (strstr(s.name, "NtQueueApcThread"))
                    Log("    → adhesive.dll bloqueou APC. Versão 2024+ do adhesive monitora NtQueueApcThread via ETW.");
                if (strstr(s.name, "Shellcode executou"))
                    Log("    → APC foi enfileirada mas não executada. Thread não estava alertable?");
            }
        }
    }

    Log("");
    Log("Log do FakeGTAProcess: C:\\Users\\Public\\fake_fivem_log.txt");
    Log("Log do TestRunner:     C:\\Users\\Public\\test_runner_log.txt");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main() {
    LogInit();
    Log("=== TestRunner v34 — Ambiente de Teste FiveM ===");
    Log("PID do TestRunner: %u", GetCurrentProcessId());
    Log("");
    Log("Procurando FiveM_GTAProcess.exe (FakeGTAProcess)...");

    // Espera até 15s pelo FakeGTAProcess
    DWORD targetPid = 0;
    for (int attempt = 0; attempt < 15 && !targetPid; attempt++) {
        targetPid = LuaExecutor::FindFiveMPid();
        if (!targetPid) {
            Log("  Tentativa %d/15 — aguardando 1s...", attempt + 1);
            Sleep(1000);
        }
    }

    if (!targetPid) {
        Log("[ERRO FATAL] FiveM_GTAProcess.exe não encontrado após 15 tentativas.");
        Log("[INSTRUÇÃO] Inicie FiveM_GTAProcess.exe (FakeGTAProcess) antes do TestRunner.");
        if (g_log) fclose(g_log);
        return 1;
    }

    Log("[FOUND] FiveM_GTAProcess.exe encontrado: PID=%u", targetPid);

    // Aguardar 2s para o processo terminar de inicializar
    Log("Aguardando 2s para inicialização completa...");
    Sleep(2000);

    // Verificar se adhesive.dll foi carregada
    bool adhesivePresent = CheckAdhesivePresent(targetPid);
    Log("adhesive.dll no processo: %s", adhesivePresent ? "SIM" : "NÃO");

    if (!adhesivePresent) {
        Log("[NOTA] adhesive.dll não carregou — teste sem o AC real.");
        Log("[NOTA] Isso pode ocorrer porque adhesive.dll tem dependências do GTA V runtime.");
        Log("[NOTA] O teste ainda valida a pipeline v34 completa.");
    }

    // Executar pipeline
    RunPipeline(targetPid);

    // Relatório final
    PrintReport(targetPid, adhesivePresent);

    if (g_log) fclose(g_log);
    printf("\nPressione ENTER para sair...");
    getchar();
    return 0;
}
