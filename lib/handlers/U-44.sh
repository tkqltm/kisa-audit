#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-44: tftp, talk 서비스 비활성화 (중요도: 상)
# KISA 가이드: tftp(69), talk(517), ntalk(518) 서비스 비활성화.
#
# Rocky 8/9/10:
#   - talk/ntalk: RHEL 7부터 기본 저장소 제거 → 미설치 시 N/A.
#   - tftp-server: 설치 가능. tftp.service 또는 tftp.socket 확인.
#
# 조치 전략:
#   관련 서비스/소켓 없음 → N/A
#   활성화 시 disable+mask
#   xinetd 기반 설정 파일 있으면 disable=yes
#
# 롤백: backup_file + _queue_rollback systemctl_state

h_U_44_meta() {
    cat <<'JSON'
{
  "code": "U-44",
  "title": "tftp, talk 서비스 비활성화",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "안전하지 않거나 불필요한 서비스를 제거함으로써 시스템 보안성 및 리소스의 효율적 운용하기 위함",
  "threat": "사용하지 않는 서비스나 취약점이 발표된 서비스 운용 시 공격 시도 가능한 위험이 존재함",
  "criterion_good": "tftp, talk, ntalk 서비스가 비활성화된 경우",
  "criterion_bad": "tftp, talk, ntalk 서비스가 활성화된 경우",
  "action_method": "불필요한 tftp, talk, ntalk 서비스 비활성화 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "tftp, talk, ntalk 서비스의 활성화 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-44 (2026 ver.)"
  ]
}
JSON
}

_u_44_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: tftp/talk/ntalk 의 systemd unit 및 xinetd 설정 점검"
        echo
        echo "## systemd 단위(.service/.socket) 상태"
        local _name _u
        while IFS= read -r _name; do
            for _u in "${_name}.service" "${_name}.socket"; do
                printf '%-20s is-enabled=%s   is-active=%s\n' \
                    "$_u" \
                    "$(systemctl is-enabled "$_u" 2>&1)" \
                    "$(systemctl is-active  "$_u" 2>&1)"
            done
        done < <(_u44_target_names)
        echo
        echo "## /etc/xinetd.d/ 의 tftp/talk/ntalk 파일 (disable 라인)"
        for _name in tftp talk ntalk; do
            if [[ -f "/etc/xinetd.d/$_name" ]]; then
                echo "### /etc/xinetd.d/$_name"
                grep -nE '^[[:space:]]*disable' "/etc/xinetd.d/$_name" 2>/dev/null || echo "(disable 라인 없음 — 활성화)"
            fi
        done
        echo
        echo "## xinetd 서비스 상태"
        echo "is-enabled xinetd: $(systemctl is-enabled xinetd 2>&1)"
        echo "is-active  xinetd: $(systemctl is-active  xinetd 2>&1)"
    } | _evidence_capture "$label"
}


_u44_target_names() { printf 'tftp\ntalk\nntalk'; }

_u44_active_systemd() {
    local name
    while IFS= read -r name; do
        local u
        for u in "${name}.service" "${name}.socket"; do
            local st
            st="$(systemctl is-enabled "$u" 2>/dev/null || true)"
            [[ -z "$st" || "$st" == "not-found" ]] && continue
            if [[ "$st" != "disabled" && "$st" != "masked" ]]; then
                printf '%s\n' "$u"
            elif systemctl is-active "$u" >/dev/null 2>&1; then
                printf '%s\n' "$u"
            fi
        done
    done < <(_u44_target_names)
}

_u44_active_xinetd() {
    local d=/etc/xinetd.d
    [[ -d "$d" ]] || return 0
    local name
    while IFS= read -r name; do
        local f="$d/$name"
        [[ -f "$f" ]] || continue
        if ! grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" 2>/dev/null; then
            printf '%s\n' "$f"
        fi
    done < <(_u44_target_names)
}

_u44_any_unit_exists() {
    local name
    while IFS= read -r name; do
        local u
        for u in "${name}.service" "${name}.socket"; do
            local st
            st="$(systemctl is-enabled "$u" 2>/dev/null || true)"
            [[ -n "$st" && "$st" != "not-found" ]] && return 0
        done
        [[ -f "/etc/xinetd.d/$name" ]] && return 0
    done < <(_u44_target_names)
    return 1
}

h_U_44_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_44_capture_state "$KISA_PHASE"
    fi

    if ! _u44_any_unit_exists; then
        printf '양호 — tftp-server/talk 미설치(취약점 해당없음)'
        return 0
    fi

    local sys_active; sys_active="$(printf '%s' "$(_u44_active_systemd)")"
    local xi_active;  xi_active="$(printf '%s' "$(_u44_active_xinetd)")"

    if [[ -z "$sys_active" && -z "$xi_active" ]]; then
        printf '양호 — tftp/talk/ntalk 서비스 비활성화'
        return 0
    fi

    local issues=()
    [[ -n "$sys_active" ]] && issues+=("systemd 활성: $sys_active")
    [[ -n "$xi_active" ]] && issues+=("xinetd 활성: $xi_active")
    printf '취약 — %s' "${issues[*]}"
    return 1
}

h_U_44_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_44_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 이미 비활성화 — 양호' ;;
            3) printf '(dry-run) tftp/talk 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) tftp/talk 서비스 disable+mask 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_44_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 tftp/talk 비활성화'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — tftp/talk 미설치'; return 3; fi

    local changed=0

    # systemd 단위
    local u
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        local cur_state
        cur_state="$(systemctl is-enabled "$u" 2>/dev/null || true)"
        if [[ "$cur_state" != "masked" ]]; then
            _queue_rollback systemctl_state "${u}:${cur_state:-disabled}"
            systemctl disable --now "$u" 2>/dev/null || true
            systemctl mask "$u" 2>/dev/null || true
            changed=1
        fi
    done < <(_u44_active_systemd)

    # xinetd 기반
    local xf
    while IFS= read -r xf; do
        [[ -z "$xf" ]] && continue
        backup_file "$xf"
        set_kv "$xf" 'disable' 'disable = yes'
        changed=1
    done < <(_u44_active_xinetd)

    if (( changed == 1 )) && systemctl is-active xinetd >/dev/null 2>&1; then
        _queue_service_op restart xinetd
        _queue_rollback systemctl_restart xinetd
    fi

    if (( changed == 0 )); then
        printf '양호 — 이미 tftp/talk 서비스 비활성화'
        return 0
    fi

    printf '조치 완료 — tftp/talk/ntalk 서비스 disable+mask'
    return 0
}
