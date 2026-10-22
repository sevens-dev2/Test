#pragma once
// lua_payload.h — v38 Native Dispatch Feature Table
//
// v37 shipped Lua payload strings that were injected and executed via
// luaL_dostring. v38 pivots to direct native dispatch: each feature is
// now a sequence of GTA native hash calls routed through
// LuaExecutor::InvokeNative. There's no more Lua VM involvement.
//
// The old inline `const char* kSpeedOn = R"lua(...)";` constants are
// preserved as empty placeholders so legacy loader code that references
// them (e.g. button labels passed to ExecLuaAsync) still compiles —
// nobody actually sends them anywhere.
//
// New: HashNative::* constants and feature functions that drive the
// per-feature loops from the loader side.

#include "lua_exec.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>

namespace LuaPayload {

// ───────────── GTA V native hashes used by v38 features ─────────
// (Standard CFX / community native-db values. Stable across GTA
//  updates — these are the hashes the game's own scripts use.)
namespace HashNative {
    constexpr uint64_t PLAYER_PED_ID                 = 0xD80958FC74E988A6ULL;
    constexpr uint64_t PLAYER_ID                     = 0x4F8644AF03D0E0D6ULL;
    constexpr uint64_t GET_PLAYER_PED                = 0x43A66C31C68491C0ULL;

    constexpr uint64_t SET_PED_MOVE_RATE_OVERRIDE    = 0x085BF80FA50A39D1ULL;
    constexpr uint64_t SET_ENTITY_INVINCIBLE         = 0x3882114BDE571AD4ULL;
    constexpr uint64_t SET_PED_CAN_RAGDOLL           = 0xB128377056A54E2AULL;
    constexpr uint64_t SET_SUPER_JUMP_THIS_FRAME     = 0x57FFF03E423A4C0BULL;
    constexpr uint64_t GIVE_WEAPON_TO_PED            = 0xBF0FD6E56C964FCBULL;
    constexpr uint64_t SET_PED_AMMO                  = 0x14E56BC5B5DB6A19ULL;
    constexpr uint64_t SET_CURRENT_PED_WEAPON        = 0xADF692B254977C0CULL;
    constexpr uint64_t SET_PED_SHOOT_RATE            = 0x614DA022990752DCULL;

    // Safe-list weapon hashes (small, same as v37)
    constexpr uint32_t WEAPON_KNIFE          = 0x99B507EA;
    constexpr uint32_t WEAPON_PISTOL         = 0x1B06D571;
    constexpr uint32_t WEAPON_SMG            = 0x2BE6766B;
    constexpr uint32_t WEAPON_CARBINERIFLE   = 0x83BF0278;
    constexpr uint32_t WEAPON_SNIPERRIFLE    = 0x05FC3C11;
    constexpr uint32_t WEAPON_COMBATPISTOL   = 0x5EF9FEC4;
    constexpr uint32_t WEAPON_PUMPSHOTGUN    = 0x1D073A89;
}

// ───────────── Shared cached state for the per-feature threads ───
struct SharedState {
    std::atomic<uint64_t> cached_ped_id{0};
    std::atomic<uint32_t> last_ped_refresh_ms{0};
    std::atomic<float>    speed_mult{1.5f};
    std::atomic<bool>     ac_present{false};
};
inline SharedState& Shared() {
    static SharedState s;
    return s;
}

// ───────────── Refresh cached PLAYER_PED_ID at most every 2s ─────
inline uint64_t RefreshPedId() {
    auto& S = Shared();
    uint32_t now = GetTickCount();
    if (S.cached_ped_id.load() != 0 &&
        (now - S.last_ped_refresh_ms.load()) < 2000) {
        return S.cached_ped_id.load();
    }
    uint64_t ped = 0;
    LuaExecutor::ExecResult r =
        LuaExecutor::InvokeNative(HashNative::PLAYER_PED_ID, nullptr, 0, &ped);
    if (r == LuaExecutor::ExecResult::OK && ped != 0) {
        S.cached_ped_id.store(ped);
        S.last_ped_refresh_ms.store(now);
    }
    return ped;
}

// ───────────── Feature invocation helpers ────────────────────────
// Each helper does ONE native dispatch per call. The loader spawns a
// background thread per toggled feature that calls the helper every
// 100-200ms with jitter (adhesive scan window ~250ms, so our shellcode
// usually isn't resident when a scan tick lands).

inline bool DoSpeedTick() {
    uint64_t ped = RefreshPedId();
    if (ped == 0) return false;
    float m = Shared().speed_mult.load();
    if (m < 1.0f) m = 1.0f;
    if (m > 1.8f) m = 1.8f;  // server-side plausibility clamp
    uint64_t speed_arg = 0;
    *reinterpret_cast<float*>(&speed_arg) = m;
    uint64_t args[2] = { ped, speed_arg };
    return LuaExecutor::InvokeNative(
        HashNative::SET_PED_MOVE_RATE_OVERRIDE, args, 2, nullptr)
        == LuaExecutor::ExecResult::OK;
}

inline bool DoGodTick(bool enable) {
    uint64_t ped = RefreshPedId();
    if (ped == 0) return false;
    uint64_t args[2] = { ped, enable ? 1ULL : 0ULL };
    return LuaExecutor::InvokeNative(
        HashNative::SET_ENTITY_INVINCIBLE, args, 2, nullptr)
        == LuaExecutor::ExecResult::OK;
}

inline bool DoJumpTick() {
    uint64_t pid_result = 0;
    LuaExecutor::InvokeNative(HashNative::PLAYER_ID, nullptr, 0, &pid_result);
    if (pid_result == 0) return false;
    uint64_t args[1] = { pid_result };
    return LuaExecutor::InvokeNative(
        HashNative::SET_SUPER_JUMP_THIS_FRAME, args, 1, nullptr)
        == LuaExecutor::ExecResult::OK;
}

inline bool DoNoRecoilTick() {
    uint64_t ped = RefreshPedId();
    if (ped == 0) return false;
    uint64_t rate_arg = 0;
    *reinterpret_cast<float*>(&rate_arg) = 0.0f;
    uint64_t args[2] = { ped, rate_arg };
    return LuaExecutor::InvokeNative(
        HashNative::SET_PED_SHOOT_RATE, args, 2, nullptr)
        == LuaExecutor::ExecResult::OK;
}

// Give weapons runs once (not a loop)
inline bool DoGiveAllWeapons() {
    uint64_t ped = RefreshPedId();
    if (ped == 0) return false;
    const uint32_t WEAPONS[] = {
        HashNative::WEAPON_KNIFE,
        HashNative::WEAPON_PISTOL,
        HashNative::WEAPON_SMG,
        HashNative::WEAPON_CARBINERIFLE,
        HashNative::WEAPON_SNIPERRIFLE,
        HashNative::WEAPON_COMBATPISTOL,
        HashNative::WEAPON_PUMPSHOTGUN,
    };
    bool allOk = true;
    for (uint32_t wep : WEAPONS) {
        // GIVE_WEAPON_TO_PED(ped, weapon, ammo=500, equipAsCurrent=false, isAmmoLoaded=false)
        uint64_t g_args[5] = { ped, (uint64_t)wep, 500ULL, 0ULL, 0ULL };
        if (LuaExecutor::InvokeNative(
                HashNative::GIVE_WEAPON_TO_PED, g_args, 5, nullptr)
            != LuaExecutor::ExecResult::OK) allOk = false;
        Sleep(30);  // 30ms spacing between weapon dispatches
        uint64_t a_args[3] = { ped, (uint64_t)wep, 500ULL };
        LuaExecutor::InvokeNative(HashNative::SET_PED_AMMO, a_args, 3, nullptr);
        Sleep(30);
    }
    return allOk;
}

// ─── Legacy Lua payload placeholders (empty strings now) ─────────
// Loader code may still reference these symbols by name. We keep them
// as empty strings so compilation succeeds and the loader can log
// labels/menu items without accidentally dispatching obsolete Lua.
inline const char* kPreamble       = "";
inline const char* kSafeInvoke     = "";
inline const char* kDetectAC       = "";
inline const char* kSpeedOn        = "";
inline const char* kSpeedOff       = "";
inline const char* kGodModeOn      = "";
inline const char* kGodModeOff     = "";
inline const char* kSuperJumpOn    = "";
inline const char* kSuperJumpOff   = "";
inline const char* kGiveAllWeapons = "";
inline const char* kNoRecoilOn     = "";
inline const char* kNoRecoilOff    = "";

// Legacy v34 helper — Build(payload) returned a Lua string. v38 just
// returns the same string back (loader code uses this to pass to
// ExecLuaAsync; that goes through LuaExecutor::Execute(string) which is
// now a probe for the native dispatch pipeline).
inline std::string Build(const std::string& payload) {
    return payload;
}

inline std::string BuildSpeedMult(float mult) {
    Shared().speed_mult.store(mult);
    return "/* v38: speed_mult set via LuaPayload::Shared() */";
}

// Legacy 3-arg Build used by main.cpp
inline void Build(char* dst, size_t dstSize, const char* payload) {
    if (dstSize == 0) return;
    size_t n = payload ? strlen(payload) : 0;
    if (n >= dstSize) n = dstSize - 1;
    memcpy(dst, payload ? payload : "", n);
    dst[n] = '\0';
}

} // namespace LuaPayload
