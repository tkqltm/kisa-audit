#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-52: Telnet 서비스 비활성화 (중요도: 중)
# KISA 가이드: telnet 평문 전송 위험 → telnet-server 패키지/서비스 비활성화.
#
# Rocky 8/9/10: telnet-server 미설치가 기본. 설치된 경우 telnet.socket 확인.
#   TELNET_MODE=disable (기본) → telnet.socket disable + mask
#   TELNET_MODE=enable          → telnet.socket unmask + enable + start
#                                 ⚠️ 평문 전송이라 KISA 권고 위반. 사이트 정책상 불가피한 경우만.
#   TELNET_MODE=keep            → 서비스 상태 그대로 (취약 판정 유지, 수동 조치 안내)
#
# 조치 전략:
#   1) telnet-server 미설치 → N/A
#   2) TELNET_MODE=disable → telnet.socket / telnet@.service disable + mask
#                            xinetd 기반(/etc/xinetd.d/telnet) → disable=yes
#   3) TELNET_MODE=enable  → telnet.socket unmask + enable + start (취약하나 사이트 강제)
#   4) TELNET_MODE=keep    → check 취약 판정, apply skip(return 2 manual)
#
# 롤백 전략: systemctl_state 큐잉

h_U_52_meta() {
    cat <<'JSON'
{
  "code": "U-52",
  "title": "Telnet 서비스 비활성화",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "취약한 Telnet 프로토콜을 비활성화함으로써 계정 및 중요 정보 유출 방지하기 위함",
  "threat": "원격 접속 시 Telnet 프로토콜을 사용할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 계정 및 중요 정보를 외부로 유출할 위험이 존재함",
  "criterion_good": "원격 접속 시 Telnet 프로토콜을 비활성화하고 있는 경우",
  "criterion_bad": "원격 접속 시 Telnet 프로토콜을 사용하는 경우",
  "action_method": "Telnet, FTP 등 안전하지 않은 서비스 사용을 중지하고 SSH 설치 및 사용하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "원격 접속 시 Telnet 프로토콜 사용 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-52 (2026 ver.)"
  ]
}
JSON
}

_u_52_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: Telnet 서비스 비활성화 여부"
        echo
        echo "## telnet-server 패키지 설치 여부"
        rpm -q telnet-server 2>&1 || true
        echo
        echo "## telnet 관련 systemd 단위 (telnet.socket / telnet@.service)"
        local _u
        for _u in telnet.socket telnet@.service telnet-server.service; do
            local _st_e _st_a
            _st_e="$(systemctl is-enabled "$_u" 2>&1)"
            _st_a="$(systemctl is-active  "$_u" 2>&1)"
            printf '%-22s is-enabled=%s   is-active=%s\n' "$_u" "$_st_e" "$_st_a"
        done
        echo
        echo "## xinetd 기반 telnet 설정 (disable 라인)"
        if [[ -f /etc/xinetd.d/telnet ]]; then
            grep -nE '^[[:space:]]*disable' /etc/xinetd.d/telnet 2>/dev/null || echo "(disable 라인 없음 — 활성화)"
        else
            echo "(/etc/xinetd.d/telnet 없음)"
        fi
        echo
        echo "## xinetd 서비스 상태"
        echo "is-enabled xinetd: $(systemctl is-enabled xinetd 2>&1)"
        echo "is-active  xinetd: $(systemctl is-active  xinetd 2>&1)"
        echo
        echo "## TCP 23(telnet) LISTEN 상태"
        if command -v ss >/dev/null 2>&1; then
            ss -tlnp 2>/dev/null | awk 'NR==1 || $4 ~ /:23$/' || true
        fi
        echo
        echo "## 환경변수: TELNET_MODE=${TELNET_MODE:-(미설정)}"
    } | _evidence_capture "$label"
}


_u52_xinetd_conf() { printf '/etc/xinetd.d/telnet'; }

_u52_pkg_installed() {
    rpm -q telnet-server >/dev/null 2>&1
}

_u52_telnet_units() {
    systemctl list-units --all --type=service --type=socket 2>/dev/null \
        | awk '{print $1}' | grep -iE '^telnet' | grep -v '^$' || true
}

_u52_xinetd_active() {
    local f; f="$(_u52_xinetd_conf)"
    [[ -f "$f" ]] || return 1
    grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" && return 1
    return 0
}

_u52_any_active() {
    local units; units="$(_u52_telnet_units)"
    [[ -n "$units" ]] && return 0
    _u52_xinetd_active && return 0
    _u52_pkg_installed && return 0
    return 1
}

h_U_52_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_52_capture_state "$KISA_PHASE"
    fi

    if ! _u52_any_active 2>/dev/null; then
        if ! _u52_pkg_installed; then
            printf '양호 — telnet-server 미설치(취약점 해당없음)'
            return 0
        fi
    fi

    local mode="${TELNET_MODE:-disable}"
    local units; units="$(_u52_telnet_units)"

    # TELNET_MODE=enable: telnet 서비스가 active 면 양호 판정 (사이트 정책으로 인한 의도적 운영)
    if [[ "$mode" == "enable" ]]; then
        if [[ -n "$units" ]] || _u52_xinetd_active; then
            printf '양호 — telnet 서비스 활성(TELNET_MODE=enable, 사이트 정책 — 평문 전송 위험 인지 필요)'
            return 0
        fi
        printf '취약 — TELNET_MODE=enable 이지만 telnet 서비스 비활성 상태'
        return 1
    fi

    if [[ -n "$units" ]]; then
        printf '취약 — telnet 서비스/소켓 활성화됨: %s' "$(printf '%s' "$units" | tr '\n' ' ')"
        return 1
    fi
    if _u52_xinetd_active; then
        printf '취약 — xinetd 기반 telnet 활성화됨'
        return 1
    fi
    if _u52_pkg_installed; then
        printf '양호 — telnet-server 설치됐으나 서비스 비활성화 상태'
        return 0
    fi

    printf '양호 — telnet-server 미설치(취약점 해당없음)'
    return 0
}

h_U_52_apply() {
    local mode="${TELNET_MODE:-disable}"

    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u52_pkg_installed; then
            printf '(dry-run) telnet-server 미설치, 조치 불필요(N/A)'
            return 0
        fi
        case "$mode" in
            enable)  printf '(dry-run) telnet.socket unmask + enable + start 예정 (TELNET_MODE=enable, ⚠️ 평문 전송 위험)' ;;
            keep)    printf '(dry-run) TELNET_MODE=keep — 비활성화 생략(manual)' ;;
            *)       printf '(dry-run) telnet 서비스/소켓 disable+mask 예정' ;;
        esac
        return 0
    fi

    if ! _u52_pkg_installed; then
        printf '해당없음 — telnet-server 미설치'
        return 3
    fi

    local rc; h_U_52_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 telnet 비활성화 상태'
        return 0
    fi

    # TELNET_MODE=enable: telnet 살리기 (사이트 정책상 강제 운영)
    if [[ "$mode" == "enable" ]]; then
        local target_unit="telnet.socket"
        # Rocky 8 은 telnet.socket, 일부 환경은 telnet@.service
        if ! systemctl list-unit-files telnet.socket 2>/dev/null | grep -q telnet.socket; then
            target_unit="telnet@.service"
        fi
        # systemctl is-enabled 는 disabled/static 상태에서 stdout="disabled" + exit=1 을 모두 반환할 수 있어
        # `cmd || printf` 패턴이 두 출력을 합쳐 "disabled\ndisabled" 같은 잘못된 args 를 만든다.
        # 따라서 명시적으로 stdout 만 캡처하고, 빈 경우만 fallback.
        local cur_state
        cur_state="$(systemctl is-enabled "$target_unit" 2>/dev/null)"
        cur_state="${cur_state%$'\n'*}"   # 첫 줄만 사용
        [[ -z "$cur_state" ]] && cur_state="disabled"
        _queue_rollback systemctl_state "${target_unit}:${cur_state}"

        systemctl unmask "$target_unit" 2>/dev/null || true
        systemctl enable --now "$target_unit" 2>/dev/null || true

        # xinetd 기반 환경
        local xf; xf="$(_u52_xinetd_conf)"
        if [[ -f "$xf" ]]; then
            backup_file "$xf"
            set_kv "$xf" 'disable' 'disable = no'
            if systemctl is-enabled xinetd >/dev/null 2>&1; then
                _queue_service_op restart xinetd
                _queue_rollback   systemctl_restart xinetd
            fi
        fi

        printf '조치 완료 — telnet.socket unmask + enable + start (TELNET_MODE=enable, ⚠️ 평문 전송 — SSH 전환 권고)'
        return 0
    fi

    if [[ "$mode" == "keep" ]]; then
        printf '수동 조치 필요 — TELNET_MODE=keep 로 Telnet 비활성화 생략\n조치: telnet.socket disable+mask 또는 SSH 전환'
        return 2
    fi

    # TELNET_MODE=disable (기본)
    local changed=0

    # xinetd 기반 처리
    local xf; xf="$(_u52_xinetd_conf)"
    if [[ -f "$xf" ]] && _u52_xinetd_active; then
        backup_file "$xf"
        set_kv "$xf" 'disable' 'disable = yes'
        changed=1
        if systemctl is-active xinetd >/dev/null 2>&1; then
            _queue_service_op restart xinetd
            _queue_rollback   systemctl_restart xinetd
        fi
    fi

    # systemd 기반 처리
    local svc
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        local cur_state
        cur_state="$(systemctl is-enabled "$svc" 2>/dev/null || printf 'disabled')"
        if [[ "$cur_state" != "masked" ]]; then
            _queue_rollback systemctl_state "${svc}:${cur_state}"
            systemctl disable --now "$svc" 2>/dev/null || true
            systemctl mask "$svc" 2>/dev/null || true
            changed=1
        fi
    done < <(_u52_telnet_units)

    if (( changed == 0 )); then
        printf '양호 — 이미 telnet 서비스 비활성화 상태'
        return 0
    fi

    printf '조치 완료 — telnet 서비스 disable+mask'
    return 0
}
