// main.cpp — FiveMMenu Pro v34 (Lua Executor / Eulen-style)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  ARQUITETURA v34 — SEM DLL INJECTION
//  ─────────────────────────────────────
//  Cada ação do usuário no menu Win32 dispara um script Lua que é executado
//  DENTRO do runtime Lua existente do FiveM, sem injetar nenhuma DLL.
//
//  Fluxo:
//    1. Usuário abre o loader .exe
//    2. Clica "Ativar Trainer" — loader verifica que FiveM está rodando
//    3. Cada toggle/botão chama LuaExecutor::Execute(script_lua)
//    4. Execute() localiza citizen-scripting-lua54.dll no FiveM, resolve
//       luaL_dostring, escreve shellcode+script em memória alocada, e executa
//       via APC injection em thread alertable
//    5. O script Lua usa Citizen.InvokeNative para aplicar o hack
//    6. Sem DLL no processo, sem IMAGE VAD entry, shellcode liberado logo após
//
//  Comparação v33 (DLL injection) vs v34 (Lua executor):
//    v33: VAD PRIVATE → IMAGE (LoadLibrary) → PE header wipe → cfx scan detecta
//    v34: ~2KB shellcode PRIVATE temporário → zero PE header → auto-liberado
//
//  Plataforma: Windows x64 | MSVC 2022+
// ═══════════════════════════════════════════════════════════════════════════════

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Comctl32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>

#include "../lua_executor/lua_exec.h"
#include "../lua_executor/lua_payload.h"

// ─── IDs dos controles ────────────────────────────────────────────────────────
constexpr int ID_CHECK_SPEED   = 101;
constexpr int ID_SLIDER_SPEED  = 102;
constexpr int ID_CHECK_GOD     = 103;
constexpr int ID_CHECK_AMMO    = 104;
constexpr int ID_CHECK_RECOIL  = 105;
constexpr int ID_CHECK_JUMP    = 106;
constexpr int ID_BTN_WEAPONS   = 107;
constexpr int ID_BTN_ACTIVATE  = 108;  // "Ativar Trainer"

// ─── Handles de controles ─────────────────────────────────────────────────────
static HWND g_checkSpeed   = nullptr;
static HWND g_sliderSpeed  = nullptr;
static HWND g_labelSpeed   = nullptr;
static HWND g_checkGod     = nullptr;
static HWND g_checkAmmo    = nullptr;
static HWND g_checkRecoil  = nullptr;
static HWND g_checkJump    = nullptr;
static HWND g_btnWeapons   = nullptr;
static HWND g_btnActivate  = nullptr;
static HWND g_labelStatus  = nullptr;

// ─── Estado da aplicação ──────────────────────────────────────────────────────
static std::atomic<bool>  g_trainerReady{false};
static std::atomic<bool>  g_activateRequested{false};
static std::mutex         g_execMtx;  // serializa chamadas ao LuaExecutor

// Valores de estado dos toggles (para re-execução ao alterar speed)
static std::atomic<bool>  g_speedOn{false};
static std::atomic<float> g_speedMult{1.5f};
static std::atomic<bool>  g_godOn{false};
static std::atomic<bool>  g_jumpOn{false};
static std::atomic<bool>  g_recoilOn{false};

// ─── Cores ────────────────────────────────────────────────────────────────────
namespace Color {
    constexpr COLORREF BG      = RGB(13,  17,  23);
    constexpr COLORREF PANEL   = RGB(22,  27,  34);
    constexpr COLORREF ACCENT  = RGB(56, 139, 253);
    constexpr COLORREF TEXT    = RGB(201, 209, 217);
    constexpr COLORREF SUBTEXT = RGB(110, 118, 129);
    constexpr COLORREF GREEN   = RGB( 63, 185,  80);
    constexpr COLORREF RED     = RGB(248,  81,  73);
    constexpr COLORREF BORDER  = RGB( 48,  54,  61);
}

// ─── Estado da UI ─────────────────────────────────────────────────────────────
struct AppState {
    std::wstring statusMain = L"Aguardando FiveM...";
    std::wstring statusSub  = L"Abra o FiveM e entre em um servidor.";
    std::wstring statusLog  = L"";
    int          progress   = 0;
    bool         done       = false;
    bool         error      = false;
    HWND         hwnd       = nullptr;
};
static AppState g_appState;

static POINT g_dragStart{};
static bool  g_dragging = false;

// ─── Fontes ───────────────────────────────────────────────────────────────────
static HFONT g_fontTitle  = nullptr;
static HFONT g_fontNormal = nullptr;
static HFONT g_fontMono   = nullptr;

static void CreateFonts() {
    g_fontTitle  = CreateFontW(22, 0, 0, 0, FW_BOLD,   FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_fontNormal = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    g_fontMono   = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Consolas");
}

constexpr int WIN_W = 420;
constexpr int WIN_H = 560;

// ─── v38: dispatch nativa em background ─────────────────────────────────────
// v37 injetava scripts Lua. v38 dispara calls de native direto via
// LuaExecutor::InvokeNative (arquitetura b2802+ compatible).
static std::atomic<bool> g_ammoOn{false};

static void ExecLuaAsync(const std::string& /*script*/) {
    // v38 legacy stub — alguns call sites antigos ainda chamam.
    // O verdadeiro dispatch acontece nos StartXxxLoop abaixo.
    std::thread([]() {
        std::lock_guard<std::mutex> lk(g_execMtx);
        auto r = LuaExecutor::Execute("");  // v38 probe (chama PLAYER_PED_ID)
        if (r != LuaExecutor::ExecResult::Ok) {
            g_appState.statusLog = L"Exec err: " + std::to_wstring((int)r);
            PostMessageW(g_appState.hwnd, WM_USER + 1, 0, 0);
        }
    }).detach();
}

// Spawna thread que roda tick() enquanto flag estiver true, com jitter.
template <typename Tick>
static void StartLoop(std::atomic<bool>& flag,
                      int min_ms, int max_ms, Tick tick) {
    flag.store(true);
    std::thread([&flag, min_ms, max_ms, tick]() {
        while (flag.load()) {
            tick();
            int period = min_ms + (int)(GetTickCount() % (max_ms - min_ms + 1));
            Sleep(period);
        }
    }).detach();
}

// ─── Criar controles do painel trainer ────────────────────────────────────────
static void CreateTrainerControls(HWND hwnd) {
    if (g_btnActivate) ShowWindow(g_btnActivate, SW_HIDE);
    HFONT font = g_fontNormal;
    int y = 225;
    const int X = 20;
    const int W = WIN_W - 40;

    g_labelStatus = CreateWindowW(L"STATIC", L"[v38 Native Dispatch Ativo]",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        X, y, W, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(g_labelStatus, WM_SETFONT, (WPARAM)font, TRUE);
    y += 28;

    // SPEED HACK
    g_checkSpeed = CreateWindowW(L"BUTTON", L"Speed Hack",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        X, y, 140, 22, hwnd, (HMENU)(INT_PTR)ID_CHECK_SPEED, nullptr, nullptr);
    SendMessageW(g_checkSpeed, WM_SETFONT, (WPARAM)font, TRUE);

    g_labelSpeed = CreateWindowW(L"STATIC", L"1.5x",
        WS_CHILD | WS_VISIBLE | SS_RIGHT,
        X + W - 60, y, 60, 22, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(g_labelSpeed, WM_SETFONT, (WPARAM)font, TRUE);
    y += 24;

    g_sliderSpeed = CreateWindowW(TRACKBAR_CLASSW, L"",
        WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_NOTICKS,
        X, y, W, 24, hwnd, (HMENU)(INT_PTR)ID_SLIDER_SPEED, nullptr, nullptr);
    SendMessageW(g_sliderSpeed, TBM_SETRANGE, TRUE, MAKELPARAM(10, 100));
    SendMessageW(g_sliderSpeed, TBM_SETPOS,   TRUE, 15); // padrão 1.5x
    y += 32;

    // GOD MODE
    g_checkGod = CreateWindowW(L"BUTTON", L"God Mode (invencível)",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        X, y, W, 22, hwnd, (HMENU)(INT_PTR)ID_CHECK_GOD, nullptr, nullptr);
    SendMessageW(g_checkGod, WM_SETFONT, (WPARAM)font, TRUE);
    y += 28;

    // SUPER JUMP
    g_checkJump = CreateWindowW(L"BUTTON", L"Super Pulo",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        X, y, W, 22, hwnd, (HMENU)(INT_PTR)ID_CHECK_JUMP, nullptr, nullptr);
    SendMessageW(g_checkJump, WM_SETFONT, (WPARAM)font, TRUE);
    y += 28;

    // NO RECOIL
    g_checkRecoil = CreateWindowW(L"BUTTON", L"Sem Recuo",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        X, y, W, 22, hwnd, (HMENU)(INT_PTR)ID_CHECK_RECOIL, nullptr, nullptr);
    SendMessageW(g_checkRecoil, WM_SETFONT, (WPARAM)font, TRUE);
    y += 28;

    // AMMO (one-shot via Lua — sem toggle porque é aplicado via give_weapon)
    g_checkAmmo = CreateWindowW(L"BUTTON", L"Municao Infinita (contínua)",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        X, y, W, 22, hwnd, (HMENU)(INT_PTR)ID_CHECK_AMMO, nullptr, nullptr);
    SendMessageW(g_checkAmmo, WM_SETFONT, (WPARAM)font, TRUE);
    y += 34;

    // GIVE WEAPONS
    g_btnWeapons = CreateWindowW(L"BUTTON", L"Dar Todas as Armas (9999 ammo)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        X, y, W, 30, hwnd, (HMENU)(INT_PTR)ID_BTN_WEAPONS, nullptr, nullptr);
    SendMessageW(g_btnWeapons, WM_SETFONT, (WPARAM)font, TRUE);
}

// ─── Atualizar UI ─────────────────────────────────────────────────────────────
static void UpdateUI() { PostMessageW(g_appState.hwnd, WM_USER + 1, 0, 0); }
static void SetStatus(std::wstring main, std::wstring sub,
                      std::wstring log = L"", int prog = -1) {
    g_appState.statusMain = std::move(main);
    g_appState.statusSub  = std::move(sub);
    if (!log.empty()) g_appState.statusLog = std::move(log);
    if (prog >= 0)    g_appState.progress  = prog;
    UpdateUI();
}

// ─── WndProc ─────────────────────────────────────────────────────────────────
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    constexpr int W = WIN_W, H = WIN_H;

    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        HDC mem = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
        SelectObject(mem, bmp);

        auto fillRect = [&](int x, int y, int w, int h, COLORREF c) {
            HBRUSH br = CreateSolidBrush(c);
            RECT r{ x, y, x+w, y+h }; FillRect(mem, &r, br); DeleteObject(br);
        };
        auto drawTxt = [&](const std::wstring& s, int x, int y, COLORREF c,
                           HFONT f, int maxW = 380,
                           DWORD fmt = DT_LEFT | DT_SINGLELINE | DT_VCENTER) {
            SetBkMode(mem, TRANSPARENT);
            SetTextColor(mem, c);
            SelectObject(mem, f);
            RECT r{ x, y, x + maxW, y + 28 };
            DrawTextW(mem, s.c_str(), -1, &r, fmt);
        };

        // Background
        fillRect(0, 0, W, H,  Color::BG);
        fillRect(0, 0, W, 38, Color::PANEL);
        fillRect(0, 37, W, 1, Color::BORDER);

        // Título
        drawTxt(L"FiveMMenu  Pro", 16, 8, Color::ACCENT, g_fontTitle);
        drawTxt(L"v38 Native", W - 80, 10, Color::SUBTEXT, g_fontMono, 70, DT_RIGHT | DT_SINGLELINE);
        drawTxt(L"✕", W - 28, 10, Color::SUBTEXT, g_fontNormal, 20, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

        // Status
        COLORREF sc = g_appState.done ? Color::GREEN : (g_appState.error ? Color::RED : Color::TEXT);
        drawTxt(g_appState.statusMain, 16, 54, sc, g_fontNormal, W - 32);
        drawTxt(g_appState.statusSub,  16, 76, Color::SUBTEXT, g_fontNormal, W - 32);

        // Barra progresso
        int barY = 114, barH = 6, barW = W - 32;
        fillRect(16, barY, barW, barH, Color::PANEL);
        HBRUSH borderBr = CreateSolidBrush(Color::BORDER);
        RECT barRect{ 16, barY, 16 + barW, barY + barH };
        FrameRect(mem, &barRect, borderBr);
        DeleteObject(borderBr);
        int filled = barW * g_appState.progress / 100;
        if (filled > 0) fillRect(16, barY, filled, barH, Color::ACCENT);

        wchar_t pct[16]; swprintf_s(pct, L"%d%%", g_appState.progress);
        drawTxt(pct, W - 48, barY - 12, Color::SUBTEXT, g_fontMono, 40, DT_RIGHT | DT_SINGLELINE);

        // Log
        drawTxt(L"> " + g_appState.statusLog, 16, 130, Color::SUBTEXT, g_fontMono, W - 32);

        // Separador
        fillRect(16, 164, W - 32, 1, Color::BORDER);

        // Técnica badge
        drawTxt(L"Lua Executor  ·  Sem DLL  ·  APC Queue  ·  Eulen-style", 16, 172,
                Color::SUBTEXT, g_fontMono, W - 32);

        // Borda
        HBRUSH frameBr = CreateSolidBrush(Color::BORDER);
        RECT wr{ 0, 0, W, H };
        FrameRect(mem, &wr, frameBr);
        DeleteObject(frameBr);

        BitBlt(hdc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
        DeleteObject(bmp); DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        POINT pt{ LOWORD(lp), HIWORD(lp) };
        if (pt.x >= 392 && pt.x <= 412 && pt.y >= 8 && pt.y <= 28)
            PostQuitMessage(0);
        if (pt.y < 38) { g_dragging = true; GetCursorPos(&g_dragStart); SetCapture(hwnd); }
        return 0;
    }
    case WM_LBUTTONUP:  g_dragging = false; ReleaseCapture(); return 0;
    case WM_MOUSEMOVE:
        if (g_dragging) {
            POINT cur; GetCursorPos(&cur);
            RECT wr2; GetWindowRect(hwnd, &wr2);
            SetWindowPos(hwnd, nullptr,
                wr2.left + (cur.x - g_dragStart.x),
                wr2.top  + (cur.y - g_dragStart.y),
                0, 0, SWP_NOSIZE | SWP_NOZORDER);
            g_dragStart = cur;
        }
        return 0;

    case WM_USER + 1: InvalidateRect(hwnd, nullptr, FALSE); return 0;
    case WM_USER + 2: CreateTrainerControls(hwnd); InvalidateRect(hwnd, nullptr, FALSE); return 0;

    case WM_COMMAND: {
        int id    = LOWORD(wp);
        int notif = HIWORD(wp);

        // Botão "Ativar Trainer"
        if (id == ID_BTN_ACTIVATE && notif == BN_CLICKED) {
            g_activateRequested.store(true);
            EnableWindow(g_btnActivate, FALSE);
            SetWindowTextW(g_btnActivate, L"Conectando ao Native Dispatch...");
            return 0;
        }

        if (!g_trainerReady.load()) return 0;

        switch (id) {
        case ID_CHECK_SPEED: {
            bool on = SendMessageW(g_checkSpeed, BM_GETCHECK, 0, 0) == BST_CHECKED;
            if (on) {
                LuaPayload::Shared().speed_mult.store(g_speedMult.load());
                StartLoop(g_speedOn, 150, 220, []() { LuaPayload::DoSpeedTick(); });
            } else {
                g_speedOn.store(false);
            }
            return 0;
        }
        case ID_CHECK_GOD: {
            bool on = SendMessageW(g_checkGod, BM_GETCHECK, 0, 0) == BST_CHECKED;
            if (on) {
                StartLoop(g_godOn, 180, 260, []() { LuaPayload::DoGodTick(true); });
            } else {
                g_godOn.store(false);
                // Pulso off único
                std::thread([]() { LuaPayload::DoGodTick(false); }).detach();
            }
            return 0;
        }
        case ID_CHECK_JUMP: {
            bool on = SendMessageW(g_checkJump, BM_GETCHECK, 0, 0) == BST_CHECKED;
            if (on) {
                // Super jump precisa de taxa alta pra "colar" por frame
                StartLoop(g_jumpOn, 80, 120, []() { LuaPayload::DoJumpTick(); });
            } else {
                g_jumpOn.store(false);
            }
            return 0;
        }
        case ID_CHECK_RECOIL: {
            bool on = SendMessageW(g_checkRecoil, BM_GETCHECK, 0, 0) == BST_CHECKED;
            if (on) {
                StartLoop(g_recoilOn, 200, 300, []() { LuaPayload::DoNoRecoilTick(); });
            } else {
                g_recoilOn.store(false);
            }
            return 0;
        }
        case ID_CHECK_AMMO: {
            bool on = SendMessageW(g_checkAmmo, BM_GETCHECK, 0, 0) == BST_CHECKED;
            if (on) {
                // Loop longo (3s) — ammo não precisa reaplicar por frame
                StartLoop(g_ammoOn, 2800, 3200, []() {
                    LuaPayload::DoGiveAllWeapons();
                });
            } else {
                g_ammoOn.store(false);
            }
            return 0;
        }
        case ID_BTN_WEAPONS:
            if (notif == BN_CLICKED) {
                std::thread([]() {
                    bool ok = LuaPayload::DoGiveAllWeapons();
                    if (ok) {
                        g_appState.statusLog = L"Armas concedidas (safe-list, 500 ammo)";
                    } else {
                        g_appState.statusLog = L"Falha ao dar armas";
                    }
                    PostMessageW(g_appState.hwnd, WM_USER + 1, 0, 0);
                }).detach();
            }
            return 0;
        }
        return 0;
    }

    case WM_HSCROLL: {
        if ((HWND)lp == g_sliderSpeed) {
            int pos  = (int)SendMessageW(g_sliderSpeed, TBM_GETPOS, 0, 0);
            float m  = pos / 10.0f;
            g_speedMult.store(m);
            // v38: thread do speed hack lê Shared().speed_mult a cada tick
            LuaPayload::Shared().speed_mult.store(m);
            wchar_t txt[32]; swprintf_s(txt, L"%.1fx", m);
            SetWindowTextW(g_labelSpeed, txt);
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ─── Thread de ativação ───────────────────────────────────────────────────────
static void ActivationThread() {
    SetStatus(L"Pronto — Entre num servidor FiveM",
              L"Carregue completamente na cidade, depois clique ATIVAR TRAINER.",
              L"Aguardando ativação", 0);

    while (!g_activateRequested.load()) Sleep(100);

    SetStatus(L"Conectando ao Native Dispatch...", L"Localizando rage-scripting-five.dll...",
              L"Scanning...", 20);

    // Tenta encontrar FiveM (máx 10 tentativas de 1s)
    DWORD pid = 0;
    for (int attempt = 0; attempt < 10 && !pid; ++attempt) {
        pid = LuaExecutor::FindFiveMPid();
        if (!pid) {
            SetStatus(L"FiveM não detectado...",
                      L"Certifique-se de estar numa cidade (não na tela de loading).",
                      L"Tentativa " + std::to_wstring(attempt + 1) + L"/10", 10);
            Sleep(1000);
        }
    }

    if (!pid) {
        SetStatus(L"FiveM não encontrado",
                  L"Abra o FiveM, entre numa cidade, e clique Ativar de novo.",
                  L"Erro: PID=0", 0);
        g_appState.error = true;
        // Reset para nova tentativa
        g_activateRequested.store(false);
        EnableWindow(g_btnActivate, TRUE);
        SetWindowTextW(g_btnActivate, L"ATIVAR TRAINER (tente de novo)");
        UpdateUI();
        return;
    }

    SetStatus(L"FiveM detectado! PID: " + std::to_wstring(pid),
              L"Localizando rage-scripting-five.dll...", L"PID=" + std::to_wstring(pid), 40);

    // Abre handle do processo
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    if (!hProc) {
        SetStatus(L"Acesso negado ao FiveM",
                  L"Execute o loader como Administrador.",
                  L"OpenProcess failed", 0);
        g_appState.error = true; UpdateUI();
        return;
    }

    // Verifica citizen-scripting-lua54.dll
    LPVOID luaBase = nullptr;
    SIZE_T luaSize = 0;
    if (!LuaExecutor::FindLuaDll(hProc, &luaBase, &luaSize)) {
        CloseHandle(hProc);
        SetStatus(L"rage-scripting-five.dll não encontrada",
                  L"Entre numa cidade primeiro (não loading screen).",
                  L"Script engine DLL not found", 0);
        g_appState.error = true; UpdateUI();
        return;
    }

    SetStatus(L"Script engine localizado!", L"Resolvendo GetNativeHandler...",
              L"rage-scripting-five.dll OK", 60);

    // Verifica rage::scrEngine::GetNativeHandler
    LPVOID pGetNative = LuaExecutor::ResolveLuaDostring(hProc, luaBase, luaSize);
    CloseHandle(hProc);

    if (!pGetNative) {
        SetStatus(L"GetNativeHandler não resolvido",
                  L"rage-scripting-five.dll encontrada mas sem export esperado.",
                  L"Export resolve failed", 0);
        g_appState.error = true; UpdateUI();
        return;
    }

    SetStatus(L"Native Dispatch Pronto!", L"Pipeline conectada. Use os controles abaixo.",
              L"GetNativeHandler=" + std::to_wstring((UINT64)pGetNative), 100);

    g_appState.done = true;
    g_trainerReady.store(true);
    PostMessageW(g_appState.hwnd, WM_USER + 2, 0, 0); // Mostra controles
}

// ─── WinMain ─────────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    // Limpa log de execução
    DeleteFileA("C:\\Users\\Public\\fivem_lua_exec.txt");

    CreateFonts();

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_BAR_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"FiveMMenuLoaderV38";  // deve bater com CreateWindowExW abaixo
    wc.hbrBackground = CreateSolidBrush(Color::BG);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        L"FiveMMenuLoaderV38", L"FiveMMenu Pro v38",
        WS_POPUP | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, WIN_W, WIN_H,
        nullptr, nullptr, hInst, nullptr);

    // v37 defensive: fail loud, not silent. Mismatch entre
    // RegisterClassExW / CreateWindowExW ou falha de registro
    // deixaria hwnd=nullptr e um processo zumbi sem UI.
    if (!hwnd) {
        wchar_t buf[256];
        swprintf_s(buf, L"CreateWindowExW falhou. GetLastError=%lu", GetLastError());
        MessageBoxW(nullptr, buf, L"FiveMMenu Pro v38 — erro fatal", MB_ICONERROR);
        return 1;
    }

    // Centraliza no monitor primario (usa SM_CXSCREEN/CYSCREEN —
    // se o monitor primario mudou, cai no CW_USEDEFAULT original).
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    if (sw > WIN_W && sh > WIN_H) {
        SetWindowPos(hwnd, HWND_TOP, (sw - WIN_W) / 2, (sh - WIN_H) / 2, 0, 0, SWP_NOSIZE);
    }

    g_appState.hwnd = hwnd;
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // Botão Ativar (abaixo da barra de status)
    g_btnActivate = CreateWindowW(L"BUTTON", L"ATIVAR TRAINER (entre na cidade primeiro)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 193, WIN_W - 40, 36, hwnd, (HMENU)(INT_PTR)ID_BTN_ACTIVATE, hInst, nullptr);
    SendMessageW(g_btnActivate, WM_SETFONT, (WPARAM)g_fontNormal, TRUE);

    // Thread de ativação
    std::thread(ActivationThread).detach();

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    DeleteObject(g_fontTitle);
    DeleteObject(g_fontNormal);
    DeleteObject(g_fontMono);
    return 0;
}
