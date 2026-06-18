#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-43: NIS, NIS+ 점검 (중요도: 상)
# KISA 가이드: NIS 서비스(ypserv, ypbind 등) 비활성화 여부 점검.
#
# Rocky 8/9/10: RHEL 8부터 NIS(yp rpms) 패키지가 기본 저장소에서 제거됨.
#   → 미설치 시 N/A.
#   ypserv, ypbind, ypxfrd, rpc.yppasswdd, rpc.ypupdated 점검.
#
# 조치 전략:
#   NIS 패키지 미설치 → N/A
#   서비스 활성화 시 disable+mask
#
# 롤백: _queue_rollback systemctl_state

h_U_43_meta() {
    cat <<'JSON'
{
  "code": "U-43",
  "title": "NIS, NIS+ 점검",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "안전하지 않은 NIS 서비스를 비활성화하고 안전한 NIS+ 서비스를 활성화하여 시스템의 보안성을 높이기 위함",
  "threat": "NIS 서비스가 활성화된 경우, 비인가자가 타 시스템의 root 권한까지 탈취할 수 있는 위험이 존재함",
  "criterion_good": "NIS 서비스가 비활성화되어 있거나, 불가피하게 사용 시 NIS+ 서비스를 사용하는 경우",
  "criterion_bad": "NIS 서비스가 활성화된 경우",
  "action_method": "NIS 관련 서비스 비활성화 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "안전하지 않은 NIS 서비스의 비활성화, 안전한 NIS+ 서비스의 활성화 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-43 (2026 ver.)"
  ]
}
JSON
}

_u_43_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 각 NIS 서비스에 대해 systemctl is-enabled / is-active 확인"
        local svc
        while IFS= read -r svc; do
            [[ -z "$svc" ]] && continue
            printf '%-22s is-enabled=%s   is-active=%s\n' \
                "$svc" \
                "$(systemctl is-enabled "$svc" 2>&1)" \
                "$(systemctl is-active  "$svc" 2>&1)"
        done < <(_u43_nis_svcs)
        echo
        echo "# NIS 관련 패키지 설치 여부"
        rpm -q ypserv ypbind yp-tools 2>&1 || true
        echo
        echo "# /etc/yp.conf 활성 라인"
        if [[ -f /etc/yp.conf ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/yp.conf 2>/dev/null || echo "(활성 항목 없음)"
        else
            echo "(/etc/yp.conf 없음)"
        fi
    } | _evidence_capture "$label"
}


_u43_nis_svcs() {
    cat <<'EOF'
ypserv
ypbind
ypxfrd
rpc.yppasswdd
rpc.ypupdated
EOF
}

_u43_any_installed() {
    local svc
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        local state
        state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
        if [[ -n "$state" && "$state" != "not-found" ]]; then
            return 0
        fi
    done < <(_u43_nis_svcs)
    # 패키지 존재 확인
    if rpm -q ypserv ypbind yp-tools >/dev/null 2>&1; then return 0; fi
    return 1
}

h_U_43_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_43_capture_state "$KISA_PHASE"
    fi

    if ! _u43_any_installed; then
        printf '양호 — NIS(ypserv/ypbind) 패키지 미설치(취약점 해당없음)'
        return 0
    fi

    local active=()
    local svc
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        local state
        state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
        [[ -z "$state" || "$state" == "not-found" ]] && continue
        if [[ "$state" != "disabled" && "$state" != "masked" ]]; then
            active+=("$svc($state)")
        elif systemctl is-active "$svc" >/dev/null 2>&1; then
            active+=("$svc(실행중)")
        fi
    done < <(_u43_nis_svcs)

    if (( ${#active[@]} == 0 )); then
        printf '양호 — NIS 서비스 비활성화됨'
        return 0
    fi

    printf '취약 — NIS 서비스 활성화: %s' "${active[*]}"
    return 1
}

h_U_43_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_43_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) NIS 서비스 이미 비활성화 — 양호' ;;
            3) printf '(dry-run) NIS 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) NIS 서비스 disable+mask 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_43_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — NIS 서비스 이미 비활성화됨'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — NIS 미설치'; return 3; fi

    local changed=0
    local svc
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        local state
        state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
        [[ -z "$state" || "$state" == "not-found" ]] && continue

        if [[ "$state" != "disabled" && "$state" != "masked" ]]; then
            _queue_rollback systemctl_state "${svc}:${state}"
            systemctl disable --now "$svc" 2>/dev/null || true
            systemctl mask "$svc" 2>/dev/null || true
            changed=1
        elif systemctl is-active "$svc" >/dev/null 2>&1; then
            systemctl stop "$svc" 2>/dev/null || true
            changed=1
        fi
    done < <(_u43_nis_svcs)

    if (( changed == 0 )); then
        printf '양호 — NIS 서비스 이미 비활성화됨'
        return 0
    fi

    printf '조치 완료 — NIS 서비스(ypserv/ypbind 등) disable+mask'
    return 0
}
