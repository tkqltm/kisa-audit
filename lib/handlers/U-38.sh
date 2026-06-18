#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-38: DoS 공격에 취약한 서비스 비활성화 (중요도: 상)
# KISA 가이드: echo(7), discard(9), daytime(13), chargen(19) 서비스 비활성화.
#
# Rocky 8/9/10: xinetd 미설치 시 해당없음(N/A).
#   xinetd 설치 시: /etc/xinetd.d/{echo,discard,daytime,chargen}-{stream,dgram} 확인.
#   systemd 기반 소켓/서비스 단위도 확인.
#
# 조치 전략:
#   1) xinetd 미설치 + systemd 소켓/서비스 없음 → N/A
#   2) xinetd 설정 파일 존재 시 disable=yes 로 수정 후 xinetd restart
#   3) systemd 소켓/서비스 존재 시 disable+mask
#
# 롤백: backup_file + _queue_rollback systemctl_state

h_U_38_meta() {
    cat <<'JSON'
{
  "code": "U-38",
  "title": "DoS 공격에 취약한 서비스 비활성화",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "많은 취약점을 가진 echo, discard, daytime, chargen 등의 서비스를 중지하여 시스템의 보안성을 높이기 위함",
  "threat": "해당 서비스가 활성화된 경우, 시스템 정보 유출 및 DoS 공격의 대상이 될 수 있는 위험이 존재함",
  "criterion_good": "DoS 공격에 취약한 서비스가 비활성화된 경우",
  "criterion_bad": "DoS 공격에 취약한 서비스가 활성화된 경우",
  "action_method": "echo, discard, daytime, chargen 등의 서비스 비활성화 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "사용하지 않는 DoS 공격에 취약한 서비스의 실행 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-38 (2026 ver.)"
  ]
}
JSON
}

_u_38_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: DoS 취약 서비스 (echo, discard, daytime, chargen) 비활성화 여부"
        echo
        echo "## xinetd 패키지 + 서비스 상태"
        rpm -q xinetd 2>&1 || true
        echo "is-enabled xinetd: $(systemctl is-enabled xinetd 2>&1)"
        echo "is-active  xinetd: $(systemctl is-active  xinetd 2>&1)"
        echo
        echo "## 대상 서비스 systemd 단위"
        local _name _u
        for _name in echo discard daytime chargen; do
            for _u in "${_name}.socket" "${_name}-stream.socket" "${_name}-dgram.socket"; do
                local _st_e _st_a
                _st_e="$(systemctl is-enabled "$_u" 2>&1)"
                if [[ "$_st_e" != "Failed"* ]] && [[ "$_st_e" != *"not-found"* ]]; then
                    _st_a="$(systemctl is-active  "$_u" 2>&1)"
                    printf '%-26s is-enabled=%s   is-active=%s\n' "$_u" "$_st_e" "$_st_a"
                fi
            done
        done
        echo
        echo "## xinetd 기반 설정 (/etc/xinetd.d/echo, discard, daytime, chargen)"
        for _name in echo discard daytime chargen; do
            for _u in "/etc/xinetd.d/${_name}" "/etc/xinetd.d/${_name}-stream" "/etc/xinetd.d/${_name}-dgram"; do
                if [[ -f "$_u" ]]; then
                    echo "### $_u"
                    grep -nE '^[[:space:]]*disable[[:space:]]*=' "$_u" 2>&1 || echo "(disable 라인 없음)"
                fi
            done
        done
        echo
        echo "## TCP 7/9/13/19 LISTEN 상태"
        if command -v ss >/dev/null 2>&1; then
            ss -tlnp 2>/dev/null | awk 'NR==1 || $4 ~ /:(7|9|13|19)$/' || true
        fi
    } | _evidence_capture "$label"
}


_u38_dos_names() { printf 'echo\ndiscard\ndaytime\nchargen'; }

_u38_xinetd_installed() {
    rpm -q xinetd >/dev/null 2>&1 || systemctl list-units --all 2>/dev/null | grep -q 'xinetd'
}

_u38_active_xinetd_files() {
    local d=/etc/xinetd.d
    [[ -d "$d" ]] || return 0
    local name
    while IFS= read -r name; do
        local f
        for f in "$d/${name}" "$d/${name}-stream" "$d/${name}-dgram" "$d/${name}-tcp" "$d/${name}-udp"; do
            [[ -f "$f" ]] || continue
            # disable=yes 없으면 활성
            if ! grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" 2>/dev/null; then
                printf '%s\n' "$f"
            fi
        done
    done < <(_u38_dos_names)
}

_u38_active_systemd_units() {
    # echo/discard/daytime/chargen socket 또는 service
    systemctl list-units --all --type=service --type=socket 2>/dev/null \
        | awk '{print $1}' \
        | grep -iE '^(echo|discard|daytime|chargen)' \
        | grep -v '^$' || true
}

h_U_38_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_38_capture_state "$KISA_PHASE"
    fi

    local xi_active sys_active

    xi_active="$(_u38_active_xinetd_files)"
    sys_active="$(_u38_active_systemd_units)"

    # xinetd 미설치 + systemd 소켓/서비스 없음 → 양호 (DoS 취약 서비스 존재 불가)
    if ! _u38_xinetd_installed && [[ -z "$sys_active" ]]; then
        printf '양호 — xinetd 미설치, echo/discard/daytime/chargen 서비스 없음(취약점 해당없음)'
        return 0
    fi

    local issues=()
    [[ -n "$xi_active" ]] && issues+=("xinetd DoS 서비스 활성: $xi_active")
    [[ -n "$sys_active" ]] && issues+=("systemd DoS 서비스 활성: $sys_active")

    if (( ${#issues[@]} == 0 )); then
        printf '양호 — DoS 취약 서비스(echo/discard/daytime/chargen) 모두 비활성화'
        return 0
    fi

    printf '취약 — %s' "${issues[*]}"
    return 1
}

h_U_38_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_38_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 이미 양호 — 조치 불필요' ;;
            3) printf '(dry-run) 해당없음 — xinetd 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) DoS 취약 서비스 disable 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_38_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 DoS 취약 서비스 비활성화 상태'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — xinetd 미설치'; return 3; fi

    local changed=0

    # xinetd 파일 처리
    local xf
    while IFS= read -r xf; do
        [[ -z "$xf" ]] && continue
        backup_file "$xf"
        set_kv "$xf" 'disable' 'disable = yes'
        changed=1
    done < <(_u38_active_xinetd_files)

    if (( changed == 1 )) && systemctl is-active xinetd >/dev/null 2>&1; then
        _queue_service_op restart xinetd
        _queue_rollback systemctl_restart xinetd
    fi

    # systemd 단위 처리
    local svc
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        local cur_state
        cur_state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
        if [[ "$cur_state" != "masked" ]]; then
            _queue_rollback systemctl_state "${svc}:${cur_state:-disabled}"
            systemctl disable --now "$svc" 2>/dev/null || true
            systemctl mask "$svc" 2>/dev/null || true
            changed=1
        fi
    done < <(_u38_active_systemd_units)

    if (( changed == 0 )); then
        printf '양호 — 이미 DoS 취약 서비스 비활성화'
        return 0
    fi

    printf '조치 완료 — DoS 취약 서비스(echo/discard/daytime/chargen) disable'
    return 0
}
