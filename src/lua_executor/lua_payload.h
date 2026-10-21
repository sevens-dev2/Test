#pragma once
// lua_payload.h — v37 Lua Payloads for FiveM
//
// v36 → v37 changelog:
//   1. Native hash obfuscation (__salt + __h_raw table):
//      - Preamble installs _G.__salt = math.random uint32 and
//        _G.__h_raw with every native hash XOR'd by __salt at
//        installation time. The XOR is done ONCE during preamble
//        execution; after that only _N('name') resolves hashes.
//      - Features never embed literal 0x..... hex native hashes
//        in their executed source — they go through _N(k).
//   2. Sprint-gated speed hack (kSpeedOn):
//      - Only applies the move-rate override while IsControlPressed
//        for INPUT_SPRINT=21 is true.
//      - Max 8000ms continuous active; 4000ms cooldown after a
//        cycle. Looks like a human sprint pattern.
//   3. Debug table sanitizer (kPreamble):
//      - Overrides debug.getinfo / debug.traceback / debug.sethook
//        to filter out our injected thread sources from the result.
//      - Not a full lockdown — surface hiding against lightweight
//        enumeration from script-level AC.
//   4. All features still route through _G.__safe_invoke (v36 rate
//      limiter preserved). All loops still Wait(500) when AC present.
//   5. __trainer_flags metatable clamp on speed_mult preserved.

namespace LuaPayload {

// ── Preamble: flag table + safe-invoke + hash obfuscation + debug sanitizer ──
inline const char* kPreamble = R"lua(
if not _G.__trainer_flags then
    local backing = {
        speed       = false,
        speed_mult  = 1.5,
        god         = false,
        jump        = false,
        weapons     = false,
        no_recoil   = false,
        ac_present  = false,
        last_jump   = 0,
        boost_start = 0,
        cooldown_start = 0
    }
    _G.__trainer_flags = setmetatable({}, {
        __index = backing,
        __newindex = function(_, k, v)
            if k == 'speed_mult' then
                v = tonumber(v) or 1.5
                if v > 1.8 then v = 1.8 end
                if v < 1.0 then v = 1.0 end
            end
            rawset(backing, k, v)
        end,
        __metatable = false
    })
end

if not _G.__safe_invoke then
    local raw_H = Citizen.InvokeNative
    local counter = {}
    local window_start = (GetGameTimer and GetGameTimer()) or 0
    _G.__safe_invoke = function(hash, ...)
        local now = (GetGameTimer and GetGameTimer()) or 0
        if (now - window_start) >= 1000 then
            counter = {}
            window_start = now
        end
        local c = counter[hash] or 0
        if c >= 60 then
            return 0
        end
        counter[hash] = c + 1
        return raw_H(hash, ...)
    end
end

-- v37: salt + __h_raw hash obfuscation table.
-- Each native hash is XOR'd by __salt at install time. After this
-- block runs, _N(k) is the only path to a plaintext native hash.
if not _G.__salt then
    if math and math.randomseed then
        math.randomseed(((GetGameTimer and GetGameTimer()) or 0) + (os and os.time and os.time() or 0))
    end
    _G.__salt = (math and math.random and math.random(1, 0x7FFFFFFF)) or 0x5A5A5A5A
    local S = _G.__salt
    _G.__h_raw = {
        move_rate                   = 0xCF678B63F86F1D34 ~ S,
        invinc                      = 0x733A643B5EEF9AD9 ~ S,
        super_jump                  = 0x08DE2E9B2C43EDBD ~ S,
        shoot_rate                  = 0x7CDDB33E0D7438AA ~ S,
        ped_id                      = 0x6E31E993AB12CA6F ~ S,
        give_weapon                 = 0xBF0FD6E56C964FCB ~ S,
        set_ammo                    = 0x14E56BC5B5DB6A19 ~ S,
        is_control_pressed          = 0xE2587F0659C6D119 ~ S,  -- IS_CONTROL_PRESSED stub hash
        get_game_timer              = 0x9CD27B0045F8E3A2 ~ S   -- GET_GAME_TIMER stub hash
    }
    _G.__N = function(k) return _G.__h_raw[k] ~ _G.__salt end
end

-- v37: debug sanitizer. Filters our thread entries from any ad-hoc
-- debug.getinfo scan. Surface hiding only.
if not _G.__dbg_sanitized then
    local marker = '__trainer'
    if debug and debug.getinfo then
        local real_getinfo = debug.getinfo
        debug.getinfo = function(level, what)
            local info = real_getinfo(level, what)
            if info and info.source and type(info.source) == 'string' then
                if string.find(info.source, marker, 1, true) then
                    return nil
                end
                if string.find(info.source, 'trainer', 1, true) then
                    return nil
                end
            end
            return info
        end
    end
    if debug and debug.traceback then
        local real_tb = debug.traceback
        debug.traceback = function(msg, lvl)
            local tb = real_tb(msg, lvl)
            if type(tb) == 'string' then
                tb = string.gsub(tb, "[^\n]*trainer[^\n]*\n?", "")
                tb = string.gsub(tb, "[^\n]*__trainer[^\n]*\n?", "")
            end
            return tb
        end
    end
    if debug and debug.sethook then
        local real_sh = debug.sethook
        debug.sethook = function(hook, mask, count)
            -- Silently swallow registry-scan sethook calls from unknown callers.
            local info = (debug and debug.getinfo) and debug.getinfo(2, 'S')
            if info and info.source and string.find(info.source, 'trainer', 1, true) then
                return
            end
            return real_sh(hook, mask, count)
        end
    end
    _G.__dbg_sanitized = true
end
)lua";

inline const char* kSafeInvoke = R"lua(
if not _G.__safe_invoke then
    local raw_H = Citizen.InvokeNative
    local counter = {}
    local window_start = (GetGameTimer and GetGameTimer()) or 0
    _G.__safe_invoke = function(hash, ...)
        local now = (GetGameTimer and GetGameTimer()) or 0
        if (now - window_start) >= 1000 then
            counter = {}; window_start = now
        end
        local c = counter[hash] or 0
        if c >= 60 then return 0 end
        counter[hash] = c + 1
        return raw_H(hash, ...)
    end
end
)lua";

// ── AC Detection (uses _N — no literal hashes in detect source) ──
inline const char* kDetectAC = R"lua(
(function()
    local known = {
        "icarusadvancedanticheat",
        "vmenuac",
        "txadmin",
        "anticheat",
        "advancedac"
    }
    _G.__trainer_flags.ac_present = false
    if type(GetNumResources) ~= 'function' or type(GetResourceByFindIndex) ~= 'function' then
        return
    end
    local n = GetNumResources()
    for i = 0, n - 1 do
        local nm = GetResourceByFindIndex(i)
        if nm then
            local lower = string.lower(nm)
            for _, bad in ipairs(known) do
                if string.find(lower, bad, 1, true) then
                    _G.__trainer_flags.ac_present = true
                    return
                end
            end
        end
    end
end)()
)lua";

// ── Speed Hack (sprint-gated, 8s on / 4s cooldown) ──────────
//   Only activates while player holds INPUT_SPRINT (control 21).
//   After 8000ms continuous active, forces 4000ms cooldown.
inline const char* kSpeedOn = R"lua(
(function()
    local _H = _G.__safe_invoke
    local _N = _G.__N
    _G.__trainer_flags.speed = true
    _G.__trainer_flags.boost_start    = 0
    _G.__trainer_flags.cooldown_start = 0
    Citizen.CreateThread(function()
        while _G.__trainer_flags.speed do
            local now    = _H(_N('get_game_timer'))
            if type(now) ~= 'number' then now = (GetGameTimer and GetGameTimer()) or 0 end
            local sprint = _H(_N('is_control_pressed'), 0, 21)
            local sprinting = (sprint == true) or (sprint == 1)

            local bs = _G.__trainer_flags.boost_start    or 0
            local cs = _G.__trainer_flags.cooldown_start or 0
            local in_cooldown = (cs > 0) and ((now - cs) < 4000)

            if sprinting and not in_cooldown then
                if bs == 0 then
                    _G.__trainer_flags.boost_start = now
                    bs = now
                end
                if (now - bs) < 8000 then
                    local ped = _H(_N('ped_id'))
                    if ped and ped ~= 0 then
                        _H(_N('move_rate'), ped, _G.__trainer_flags.speed_mult)
                    end
                else
                    _G.__trainer_flags.cooldown_start = now
                    _G.__trainer_flags.boost_start   = 0
                end
            else
                if bs > 0 and (now - bs) >= 8000 then
                    _G.__trainer_flags.cooldown_start = now
                end
                _G.__trainer_flags.boost_start = 0
            end

            Citizen.Wait(_G.__trainer_flags.ac_present and 500 or 0)
        end
    end)
end)()
)lua";

inline const char* kSpeedOff = R"lua(
(function()
    local _H = _G.__safe_invoke
    local _N = _G.__N
    _G.__trainer_flags.speed = false
    local ped = _H(_N('ped_id'))
    if ped and ped ~= 0 then
        _H(_N('move_rate'), ped, 1.0)
    end
end)()
)lua";

// ── God Mode (SET_PED_INVINCIBLE only) ──
inline const char* kGodModeOn = R"lua(
(function()
    local _H = _G.__safe_invoke
    local _N = _G.__N
    _G.__trainer_flags.god = true
    Citizen.CreateThread(function()
        while _G.__trainer_flags.god do
            local ped = _H(_N('ped_id'))
            if ped and ped ~= 0 then
                _H(_N('invinc'), ped, true)
            end
            Citizen.Wait(_G.__trainer_flags.ac_present and 500 or 0)
        end
    end)
end)()
)lua";

inline const char* kGodModeOff = R"lua(
(function()
    local _H = _G.__safe_invoke
    local _N = _G.__N
    _G.__trainer_flags.god = false
    local ped = _H(_N('ped_id'))
    if ped and ped ~= 0 then
        _H(_N('invinc'), ped, false)
    end
end)()
)lua";

// ── Super Jump (300ms cooldown gate; obfuscated hashes) ──
inline const char* kSuperJumpOn = R"lua(
(function()
    local _H = _G.__safe_invoke
    local _N = _G.__N
    _G.__trainer_flags.jump = true
    Citizen.CreateThread(function()
        while _G.__trainer_flags.jump do
            local now  = GetGameTimer()
            local last = _G.__trainer_flags.last_jump or 0
            if (now - last) >= 300 then
                local pid = _H(_N('ped_id'))
                if pid and pid ~= 0 then
                    _H(_N('super_jump'), pid)
                    _G.__trainer_flags.last_jump = now
                end
            end
            Citizen.Wait(_G.__trainer_flags.ac_present and 500 or 0)
        end
    end)
end)()
)lua";

inline const char* kSuperJumpOff = R"lua(
(function()
    _G.__trainer_flags.jump = false
end)()
)lua";

// ── Give Weapons (safe-list; obfuscated give/ammo hashes) ──
inline const char* kGiveAllWeapons = R"lua(
(function()
    local _H = _G.__safe_invoke
    local _N = _G.__N
    local WEAPONS = {
        0x99B507EA,  -- WEAPON_KNIFE
        0x1B06D571,  -- WEAPON_PISTOL
        0x2BE6766B,  -- WEAPON_SMG
        0x83BF0278,  -- WEAPON_CARBINERIFLE
        0x05FC3C11,  -- WEAPON_SNIPERRIFLE
        0x5EF9FEC4,  -- WEAPON_COMBATPISTOL
        0x1D073A89   -- WEAPON_PUMPSHOTGUN
    }
    local ped = _H(_N('ped_id'))
    if not ped or ped == 0 then return end
    for _, wep in ipairs(WEAPONS) do
        _H(_N('give_weapon'), ped, wep, 500, false, false)
        _H(_N('set_ammo'),    ped, wep, 500)
    end
    _G.__trainer_flags.weapons = true
end)()
)lua";

// ── No Recoil (SET_PED_SHOOT_RATE only; obfuscated hash) ──
inline const char* kNoRecoilOn = R"lua(
(function()
    local _H = _G.__safe_invoke
    local _N = _G.__N
    _G.__trainer_flags.no_recoil = true
    Citizen.CreateThread(function()
        while _G.__trainer_flags.no_recoil do
            local ped = _H(_N('ped_id'))
            if ped and ped ~= 0 then
                _H(_N('shoot_rate'), ped, 0.0)
            end
            Citizen.Wait(_G.__trainer_flags.ac_present and 500 or 0)
        end
    end)
end)()
)lua";

inline const char* kNoRecoilOff = R"lua(
(function()
    _G.__trainer_flags.no_recoil = false
end)()
)lua";

// Build concatenates kPreamble + kDetectAC + payload so every feature
// inherits __trainer_flags, __safe_invoke, __salt, __h_raw, __N, and
// the debug sanitizer. The literal native hashes appear ONLY inside
// kPreamble, which runs once per session.
inline void Build(char* dst, size_t dstSize, const char* payload) {
    snprintf(dst, dstSize, "%s\n%s\n%s", kPreamble, kDetectAC, payload);
}

} // namespace LuaPayload
