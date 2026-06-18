#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-34: Finger 서비스 비활성화 (중요도: 상)
# KISA 가이드: Finger 서비스는 원격에서 사용자 정보를 조회할 수 있어 비활성화 필요.
#
# Rocky 8/9/10: finger-server 패키지가 기본 미설치이므로 대부분 N/A.
#   - finger-server 패키지 설치 여부 확인 (rpm -q finger-server)
#   - finger.service / finger.socket 활성화 여부 확인
#   - xinetd 기반 /etc/xinetd.d/finger 존재 시 disable=yes 확인
#
# 조치 전략:
#   1) finger-server 미설치 + 관련 서비스/소켓 없음 → 해당없음(N/A)
#   2) finger-server 설치됨 또는 finger 서비스/소켓 활성화 → disable+mask
#   3) xinetd 기반 설정이 있으면 disable=yes 로 수정 후 xinetd restart
#
# 롤백 전략:
#   서비스 비활성화는 _queue_rollback systemctl_state <svc>:enabled 로 등록.

h_U_34_meta() {
    cat <<'JSON'
{
  "code": "U-34",
  "title": "Finger 서비스 비활성화",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "Finger 서비스를 통해 네트워크 외부에서 해당 시스템에 등록된 사용자 정보를 확인할 수 있어 비인가자에게 사용자 정보가 조회되는 것을 방지하기 위함",
  "threat": "Finger 서비스가 활성화되어 있을 경우, 비인가자가 Finger 서비스를 사용하여 사용자 정보를 조회한 후 비밀번호 공격을 통해 계정을 탈취할 위험이 존재함",
  "criterion_good": "Finger 서비스가 비활성화된 경우",
  "criterion_bad": "Finger 서비스가 활성화된 경우",
  "action_method": "Finger 서비스 비활성화 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "Finger 서비스 비활성화 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-34 (2026 ver.)"
  ]
}
JSON
}

_u_34_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: Finger 서비스 비활성화 여부"
        echo
        echo "## finger-server / cfingerd 패키지 설치"
        for pkg in finger-server cfingerd; do
            printf '%-14s : %s\n' "$pkg" "$(rpm -q "$pkg" 2>&1)"
        done
        echo
        echo "## finger 관련 systemd 단위"
        for u in finger.socket finger@.service cfingerd.service; do
            printf '%-22s is-enabled=%s   is-active=%s\n' \
                "$u" \
                "$(systemctl is-enabled "$u" 2>&1)" \
                "$(systemctl is-active  "$u" 2>&1)"
        done
        echo
        echo "## xinetd 기반 finger 설정 (disable 라인)"
        if [[ -f /etc/xinetd.d/finger ]]; then
            grep -nE '^[[:space:]]*disable' /etc/xinetd.d/finger 2>/dev/null || echo "(disable 라인 없음 — 활성화)"
        else
            echo "(/etc/xinetd.d/finger 없음)"
        fi
        echo
        echo "## TCP 79(finger) LISTEN 상태"
        if command -v ss >/dev/null 2>&1; then
            ss -tlnp 2>/dev/null | awk 'NR==1 || $4 ~ /:79$/' || true
        fi
    } | _evidence_capture "$label"
}


_u34_finger_svcs() {
    # finger 관련 service 및 socket unit 목록
    systemctl list-units --all --type=service --type=socket 2>/dev/null \
        | awk '{print $1}' | grep -iE '^finger' | grep -v '^$' || true
}

_u34_pkg_installed() {
    rpm -q finger-server >/dev/null 2>&1
}

_u34_xinetd_conf() { printf '/etc/xinetd.d/finger'; }

# xinetd 기반 finger 활성화 여부 (0=활성, 1=비활성/없음)
_u34_xinetd_active() {
    local f; f="$(_u34_xinetd_conf)"
    [[ -f "$f" ]] || return 1
    # disable = yes 가 있으면 비활성
    grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" && return 1
    return 0
}

h_U_34_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_34_capture_state "$KISA_PHASE"
    fi

    local pkg_installed=0 svc_active="" xinetd_active=0

    _u34_pkg_installed && pkg_installed=1

    local svcs
    svcs="$(_u34_finger_svcs)"
    if [[ -n "$svcs" ]]; then
        svc_active="$svcs"
    fi

    _u34_xinetd_active && xinetd_active=1

    if (( pkg_installed == 0 )) && [[ -z "$svc_active" ]] && (( xinetd_active == 0 )); then
        printf '양호 — finger-server 미설치, 관련 서비스/소켓 없음(취약점 해당없음)'
        return 0
    fi

    if (( pkg_installed == 1 )) || [[ -n "$svc_active" ]] || (( xinetd_active == 1 )); then
        if [[ -n "$svc_active" ]]; then
            printf '취약 — Finger 서비스 활성화됨: %s' "$svc_active"
        elif (( xinetd_active == 1 )); then
            printf '취약 — xinetd 기반 Finger 서비스 활성화됨: %s' "$(_u34_xinetd_conf)"
        else
            printf '취약 — finger-server 설치됨, 서비스 비활성화 여부 재확인 필요'
        fi
        return 1
    fi

    printf '양호 — finger-server 설치됨, 서비스 비활성화 상태'
    return 0
}

h_U_34_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_34_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 이미 양호, 조치 불필요' ;;
            3) printf '(dry-run) finger-server 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) finger 서비스 disable+mask 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_34_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 양호 상태(조치 불필요)'
        return 0
    fi
    if (( rc == 3 )); then
        printf '해당없음 — finger-server 미설치'
        return 3
    fi

    local changed=0

    # xinetd 기반 처리
    local xf; xf="$(_u34_xinetd_conf)"
    if [[ -f "$xf" ]] && _u34_xinetd_active; then
        backup_file "$xf"
        set_kv "$xf" 'disable' 'disable = yes'
        changed=1
        # xinetd 재시작 큐
        if systemctl is-active xinetd >/dev/null 2>&1; then
            _queue_service_op restart xinetd
            _queue_rollback systemctl_restart xinetd
        fi
    fi

    # systemd 기반 처리
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
    done < <(_u34_finger_svcs)

    if (( changed == 0 )); then
        printf '양호 — 이미 Finger 서비스 비활성화 상태'
        return 0
    fi

    printf '조치 완료 — Finger 서비스 disable+mask 적용'
    return 0
}
