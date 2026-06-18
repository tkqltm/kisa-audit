#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-39: 불필요한 NFS 서비스 비활성화 (중요도: 상)
# KISA 가이드: NFS_ALLOWED_NETWORKS 가 비어 있으면 NFS 서버 불필요 → disable+mask.
#              NFS_ALLOWED_NETWORKS 지정 시 → U-40 에서 접근 통제.
#
# Rocky 8/9/10: nfs-server.service 확인.
#
# 조치 전략:
#   NFS_ALLOWED_NETWORKS 빈 값 → nfs-server disable+mask
#   NFS_ALLOWED_NETWORKS 지정 → 해당없음(U-40 에서 처리)
#
# 롤백: _queue_rollback systemctl_state nfs-server:enabled

h_U_39_meta() {
    cat <<'JSON'
{
  "code": "U-39",
  "title": "불필요한 NFS 서비스 비활성화",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "NFS(Network File System) 서비스는 한 서버의 파일을 많은 서비스 서버들이 공유하여 사용할 때 이용하는 서비스지만 이를 이용한 침해사고 위험성이 높으므로 사용하지 않는 경우 중지하기 위함",
  "threat": "NFS 서비스는 서버의 디스크를 클라이언트와 공유하는 서비스로 적정한 보안 설정이 적용되어 있지 않다면 불필요한 파일 공유로 인한 유출 위험이 존재함",
  "criterion_good": "불필요한 NFS 서비스 관련 데몬이 비활성화된 경우",
  "criterion_bad": "불필요한 NFS 서비스 관련 데몬이 활성화된 경우",
  "action_method": "NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 ※ 로컬 서버에 마운트 되어 있는 디렉터리 제거 및 공유 디렉터리 제거 후 서비스 중지 가능",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "불필요한 NFS 서비스 사용 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-39 (2026 ver.)"
  ]
}
JSON
}

_u_39_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: systemctl is-enabled / is-active nfs-server"
        echo "is-enabled: $(systemctl is-enabled nfs-server 2>&1)"
        echo "is-active : $(systemctl is-active  nfs-server 2>&1)"
        echo
        echo "# nfs-utils 패키지 설치 여부"
        rpm -q nfs-utils 2>&1 || true
        echo
        echo "# /etc/exports — NFS 공유 정책 (활성 라인)"
        if [[ -f /etc/exports ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/exports 2>/dev/null || echo "(활성 export 항목 없음)"
        else
            echo "(/etc/exports 없음)"
        fi
        echo
        echo "# /etc/exports.d/*.exports 활성 라인"
        if [[ -d /etc/exports.d ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/exports.d/*.exports 2>/dev/null || echo "(없음)"
        else
            echo "(/etc/exports.d 없음)"
        fi
        echo
        echo "# 환경변수: NFS_ALLOWED_NETWORKS=${NFS_ALLOWED_NETWORKS:-(미설정)}"
    } | _evidence_capture "$label"
}


_u39_nfs_svc() { printf 'nfs-server'; }

_u39_nfs_enabled() {
    local s; s="$(systemctl is-enabled "$(_u39_nfs_svc)" 2>/dev/null || true)"
    [[ -n "$s" && "$s" != "not-found" && "$s" != "disabled" && "$s" != "masked" ]]
}

_u39_nfs_active() {
    systemctl is-active "$(_u39_nfs_svc)" >/dev/null 2>&1
}

h_U_39_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_39_capture_state "$KISA_PHASE"
    fi

    local svc; svc="$(_u39_nfs_svc)"
    local nfs_state
    nfs_state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"

    # 서비스 unit 자체가 없으면 NFS 취약점 해당없음 = 양호
    if [[ -z "$nfs_state" || "$nfs_state" == "not-found" ]]; then
        printf '양호 — nfs-server 패키지 미설치(취약점 해당없음)'
        return 0
    fi

    # NFS_ALLOWED_NETWORKS 지정 시 — 운영상 NFS 사용 허용, U-40 에서 접근통제 점검
    if [[ -n "${NFS_ALLOWED_NETWORKS:-}" ]]; then
        printf '양호 — NFS_ALLOWED_NETWORKS 지정(%s), U-40 접근통제 적용 대상' "${NFS_ALLOWED_NETWORKS}"
        return 0
    fi

    # NFS_ALLOWED_NETWORKS 없음 → NFS 서버가 비활성화 되어야 양호
    if [[ "$nfs_state" == "disabled" || "$nfs_state" == "masked" ]]; then
        if ! _u39_nfs_active; then
            printf '양호 — nfs-server 비활성화(%s)이고 실행 안 됨' "$nfs_state"
            return 0
        fi
    fi

    printf '취약 — nfs-server 활성화(%s), NFS_ALLOWED_NETWORKS 미지정으로 비활성화 필요' "$nfs_state"
    return 1
}

h_U_39_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_39_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) nfs-server 이미 비활성화 — 양호' ;;
            3) printf '(dry-run) 해당없음(미설치 또는 NFS_ALLOWED_NETWORKS 지정)' ;;
            *) printf '(dry-run) nfs-server disable+mask 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_39_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 nfs-server 비활성화 상태'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — 미설치 또는 NFS_ALLOWED_NETWORKS 지정'; return 3; fi

    local svc; svc="$(_u39_nfs_svc)"
    local cur_state
    cur_state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"

    _queue_rollback systemctl_state "${svc}:${cur_state:-disabled}"
    systemctl disable --now "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true

    # rpcbind 도 NFS 전용으로만 쓰인다면 같이 비활성화 (단, 다른 RPC 서비스 의존 가능성 있어 skip)
    # → U-42 에서 별도 처리

    printf '조치 완료 — nfs-server disable+mask'
    return 0
}
