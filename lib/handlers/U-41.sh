#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-41: 불필요한 automountd 제거 (중요도: 상)
# KISA 가이드: autofs.service(automountd) 비활성화.
#
# Rocky 8/9/10: autofs 패키지 기본 미설치 → 미설치 시 N/A.
#   점검: autofs.service 활성화 여부.
#
# 조치 전략:
#   autofs 미설치 → N/A
#   autofs.service 활성화됨 → disable+mask
#
# 롤백: _queue_rollback systemctl_state autofs:enabled

h_U_41_meta() {
    cat <<'JSON'
{
  "code": "U-41",
  "title": "불필요한 automountd 제거",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "로컬 공격자가 automountd 데몬에 RPC(Remote Procedure Call)를 보낼 수 있는 취약점이 존재하기 때문에 해당 서비스를 중지시키기 위함",
  "threat": "파일 시스템의 마운트 옵션을 변경하여 root 권한을 획득할 수 있으며, 로컬 공격자가 automountd 프로세스 권한으로 임의의 명령을 실행할 수 있는 위험이 존재함",
  "criterion_good": "automountd 서비스가 비활성화된 경우",
  "criterion_bad": "automountd 서비스가 활성화된 경우",
  "action_method": "automountd 서비스 비활성화 설정",
  "action_impact": "NFS 및 삼바(Samba) 서비스에서 사용 시 automountd 사용 여부 확인이 필요하며, 적용 시 CD-ROM의 자동 마운트는 이뤄지지 않음 (/etc/auto.*, /etc/auto_* 파일을 확인하여 필요 여부 확인)",
  "method": [
    "automountd 서비스 데몬의 실행 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-41 (2026 ver.)"
  ]
}
JSON
}

_u_41_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: systemctl is-enabled / is-active autofs"
        echo "is-enabled autofs: $(systemctl is-enabled autofs 2>&1)"
        echo "is-active  autofs: $(systemctl is-active  autofs 2>&1)"
        echo
        echo "# autofs 패키지 설치 여부"
        rpm -q autofs 2>&1 || true
        echo
        echo "# /etc/auto.master 활성 라인"
        if [[ -f /etc/auto.master ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/auto.master 2>/dev/null || echo "(활성 항목 없음)"
        else
            echo "(/etc/auto.master 없음)"
        fi
        echo
        echo "# /etc/auto.master.d/ 디렉터리 항목"
        if [[ -d /etc/auto.master.d ]]; then
            ls -l /etc/auto.master.d/ 2>&1
        else
            echo "(/etc/auto.master.d 없음)"
        fi
    } | _evidence_capture "$label"
}


_u41_svc() { printf 'autofs'; }

h_U_41_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_41_capture_state "$KISA_PHASE"
    fi

    local svc; svc="$(_u41_svc)"
    local state
    state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"

    if [[ -z "$state" || "$state" == "not-found" ]]; then
        printf '양호 — autofs 패키지 미설치(취약점 해당없음)'
        return 0
    fi

    local active
    active="$(systemctl is-active "$svc" 2>/dev/null || true)"

    if [[ "$state" == "masked" ]] || { [[ "$state" == "disabled" ]] && [[ "$active" != "active" ]]; }; then
        printf '양호 — autofs.service 비활성화(%s/%s)' "$state" "$active"
        return 0
    fi

    printf '취약 — autofs.service 활성화(%s/%s)' "$state" "$active"
    return 1
}

h_U_41_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_41_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) autofs 이미 비활성화 — 양호' ;;
            3) printf '(dry-run) autofs 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) autofs.service disable+mask 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_41_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 autofs.service 비활성화'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — autofs 패키지 미설치'; return 3; fi

    local svc; svc="$(_u41_svc)"
    local cur_state
    cur_state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"

    _queue_rollback systemctl_state "${svc}:${cur_state:-disabled}"
    systemctl disable --now "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true

    printf '조치 완료 — autofs.service disable+mask'
    return 0
}
