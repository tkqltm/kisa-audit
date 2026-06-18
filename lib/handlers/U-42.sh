#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-42: 불필요한 RPC 서비스 비활성화 (중요도: 상)
# KISA 가이드: rpc.cmsd, rpc.ttdbserverd, sadmind, rusersd, walld, sprayd, rstatd,
#              rpc.nisd, rexd, rpc.pcnfsd, rpc.statd, rpc.ypupdated, rpc.rquotad,
#              kcms_server, cachefsd 등 불필요한 RPC 서비스 비활성화.
#
# Rocky 8/9/10:
#   - rpcbind.service: NFS/NIS 사용 시 필요할 수 있어 직접 비활성화 금지.
#   - rpc-statd.service: 불필요 시 비활성화.
#   - rpc-gssd.service: Kerberos NFS 인증용, 불필요 시 비활성화.
#   - ypserv, ypbind 등 NIS: Rocky 8부터 기본 미설치.
#   - 위 가이드 목록의 RHEL 계열 해당 서비스명으로 매핑.
#
# 조치 전략:
#   관련 서비스 unit 없으면 N/A.
#   활성화된 불필요 RPC 서비스 disable+mask.
#   rpcbind 는 NFS_ALLOWED_NETWORKS 지정 시 유지.
#
# 롤백: _queue_rollback systemctl_state

h_U_42_meta() {
    cat <<'JSON'
{
  "code": "U-42",
  "title": "불필요한 RPC 서비스 비활성화",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "많은 취약점(버퍼 오버플로우, DoS, 원격 실행 등)이 존재하는 RPC 서비스를 비활성화하여 시스템의 보안성을 높이기 위함",
  "threat": "RPC 서비스의 취약점을 통해 비인가자가 root 권한 획득 및 각종 공격을 시도할 위험이 존재함",
  "criterion_good": "불필요한 RPC 서비스가 비활성화된 경우",
  "criterion_bad": "불필요한 RPC 서비스가 활성화된 경우",
  "action_method": "불필요한 RPC 서비스 중지 및 비활성화 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "불필요한 RPC 서비스의 실행 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-42 (2026 ver.)"
  ]
}
JSON
}

_u_42_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 각 RPC 서비스에 대해 systemctl is-enabled / is-active 확인"
        local svc
        while IFS= read -r svc; do
            [[ -z "$svc" ]] && continue
            printf '%-22s is-enabled=%s   is-active=%s\n' \
                "$svc" \
                "$(systemctl is-enabled "$svc" 2>&1)" \
                "$(systemctl is-active  "$svc" 2>&1)"
        done < <(_u42_rpc_svcs)
        echo
        echo "# rpcinfo -p (RPC 등록 서비스)"
        if command -v rpcinfo >/dev/null 2>&1; then
            rpcinfo -p 2>&1 | head -40 || true
        else
            echo "(rpcinfo 명령 없음)"
        fi
        echo
        echo "# 환경변수: NFS_ALLOWED_NETWORKS=${NFS_ALLOWED_NETWORKS:-(미설정)}"
    } | _evidence_capture "$label"
}


# 불필요한 RPC 서비스 목록 (Rocky 8/9/10 서비스명)
_u42_rpc_svcs() {
    cat <<'EOF'
rpc-statd
rpcbind
ypserv
ypbind
ypxfrd
rpc.yppasswdd
rpc.ypupdated
rpc.rquotad
EOF
}

# rpcbind 는 NFS 또는 NIS 사용 시 필요할 수 있음
_u42_rpcbind_needed() {
    [[ -n "${NFS_ALLOWED_NETWORKS:-}" ]] && return 0
    # ypbind/ypserv 가 활성화돼 있으면 rpcbind 필요
    local s
    for s in ypserv ypbind; do
        systemctl is-active "$s" >/dev/null 2>&1 && return 0
    done
    return 1
}

h_U_42_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_42_capture_state "$KISA_PHASE"
    fi

    local found=() active=()

    local svc
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        local state
        state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
        [[ -z "$state" || "$state" == "not-found" ]] && continue
        found+=("$svc")

        # rpcbind 는 NFS/NIS 사용 시 제외
        if [[ "$svc" == "rpcbind" ]] && _u42_rpcbind_needed; then
            continue
        fi

        if [[ "$state" != "disabled" && "$state" != "masked" ]]; then
            active+=("$svc($state)")
        elif systemctl is-active "$svc" >/dev/null 2>&1; then
            active+=("$svc(실행중)")
        fi
    done < <(_u42_rpc_svcs)

    if (( ${#found[@]} == 0 )); then
        printf '양호 — 불필요한 RPC 서비스 미설치(취약점 해당없음)'
        return 0
    fi

    if (( ${#active[@]} == 0 )); then
        printf '양호 — 불필요한 RPC 서비스 모두 비활성화됨'
        return 0
    fi

    printf '취약 — 활성화된 RPC 서비스: %s' "${active[*]}"
    return 1
}

h_U_42_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_42_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 양호 — 이미 불필요한 RPC 서비스가 모두 비활성화됨, 조치 불필요' ;;
            3) printf '(dry-run) 해당없음 — RPC 서비스 미설치, 조치 불필요' ;;
            *) printf '(dry-run) 불필요한 RPC 서비스 disable+mask 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_42_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 불필요한 RPC 서비스가 모두 비활성화됨'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — RPC 서비스 미설치'; return 3; fi

    local changed=0

    local svc
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        local state
        state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
        [[ -z "$state" || "$state" == "not-found" ]] && continue

        # rpcbind 는 NFS/NIS 사용 시 유지
        if [[ "$svc" == "rpcbind" ]] && _u42_rpcbind_needed; then
            continue
        fi

        if [[ "$state" != "disabled" && "$state" != "masked" ]]; then
            _queue_rollback systemctl_state "${svc}:${state}"
            systemctl disable --now "$svc" 2>/dev/null || true
            systemctl mask "$svc" 2>/dev/null || true
            changed=1
        elif systemctl is-active "$svc" >/dev/null 2>&1; then
            systemctl stop "$svc" 2>/dev/null || true
            changed=1
        fi
    done < <(_u42_rpc_svcs)

    if (( changed == 0 )); then
        printf '양호 — 이미 불필요한 RPC 서비스가 모두 비활성화됨'
        return 0
    fi

    printf '조치 완료 — 불필요한 RPC 서비스 disable+mask 처리'
    return 0
}
