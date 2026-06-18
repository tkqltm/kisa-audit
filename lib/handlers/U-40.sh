#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-40: NFS 접근 통제 (중요도: 상)
# KISA 가이드: NFS_ALLOWED_NETWORKS 지정 시 /etc/exports 에 허용 네트워크만 기재.
#              /etc/exports 소유자 root, 권한 644 이하.
#              와일드카드(*) 단독 사용 금지.
#
# 조치 전략:
#   NFS_ALLOWED_NETWORKS 미지정 → U-39 에서 NFS 비활성화 처리, 이 항목 N/A.
#   NFS_ALLOWED_NETWORKS 지정 → exports 파일 권한 644, 와일드카드 단독 사용 확인.
#     와일드카드 단독 항목 있으면 허용 네트워크 기반으로 수정(수동 권고 포함).
#   변경 후 exportfs -ra, firewalld reload 큐.
#
# 롤백: backup_file exports + _queue_rollback systemctl_reload firewalld

h_U_40_meta() {
    cat <<'JSON'
{
  "code": "U-40",
  "title": "NFS 접근 통제",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "접근 권한이 없는 비인가자의 접근을 통제하기 위함",
  "threat": "접근 통제 설정이 적절하지 않을 경우, 인증 절차 없이 비인가자가 디렉터리나 파일의 접근이 가능하며, 해당 공유 시스템에 원격으로 마운트하여 중요 파일을 변조하거나 유출할 위험이 존재함",
  "criterion_good": "접근 통제가 설정되어 있으며 NFS 설정 파일 접근 권한이 644 이하인 경우",
  "criterion_bad": "접근 통제가 설정되어 있지 않고 NFS 설정 파일 접근 권한이 644를 초과하는 경우",
  "action_method": "- NFS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - 불가피하게 사용 시 접근 통제 설정 및 NFS 설정 파일 접근 권한 644 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "NFS(Network File System)의 접근 통제 설정 적용 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-40 (2026 ver.)"
  ]
}
JSON
}

_u_40_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: NFS 접근 통제 (everyone access 차단)"
        echo
        echo "## nfs-utils 패키지 + nfs-server 서비스 상태"
        rpm -q nfs-utils 2>&1 || true
        echo "is-enabled nfs-server: $(systemctl is-enabled nfs-server 2>&1)"
        echo "is-active  nfs-server: $(systemctl is-active  nfs-server 2>&1)"
        echo
        echo "## /etc/exports — 권한 + 활성 라인"
        if [[ -f /etc/exports ]]; then
            ls -l /etc/exports 2>&1
            grep -nvE '^[[:space:]]*(#|$)' /etc/exports 2>/dev/null || echo "(활성 export 항목 없음)"
        else
            echo "(/etc/exports 없음)"
        fi
        echo
        echo "## /etc/exports.d/*.exports — 활성 라인"
        if [[ -d /etc/exports.d ]]; then
            local _f _had=0
            for _f in /etc/exports.d/*.exports; do
                [[ -f "$_f" ]] || continue
                _had=1
                echo "### $_f"
                grep -nvE '^[[:space:]]*(#|$)' "$_f" 2>/dev/null || echo "(활성 항목 없음)"
            done
            (( _had == 0 )) && echo "(*.exports 파일 없음)"
        else
            echo "(/etc/exports.d 디렉터리 없음)"
        fi
        echo
        echo "## 현재 export 상태 (exportfs -v)"
        if command -v exportfs >/dev/null 2>&1; then
            exportfs -v 2>&1 || true
        fi
        echo
        echo "## firewalld nfs/rpc 서비스 허용 여부"
        if systemctl is-active firewalld >/dev/null 2>&1 && command -v firewall-cmd >/dev/null 2>&1; then
            local _z; _z=$(firewall-cmd --get-default-zone 2>/dev/null || echo public)
            echo "default-zone: $_z"
            firewall-cmd --zone="$_z" --list-services 2>&1 || true
        fi
        echo
        echo "## 환경변수: NFS_ALLOWED_NETWORKS=${NFS_ALLOWED_NETWORKS:-(미설정)}"
    } | _evidence_capture "$label"
}


_u40_exports() { printf '/etc/exports'; }

_u40_exports_perm_ok() {
    local f; f="$(_u40_exports)"
    [[ -f "$f" ]] || return 1
    local owner perm
    owner=$(stat -c '%U' "$f" 2>/dev/null)
    perm=$(stat -c '%a' "$f" 2>/dev/null)
    [[ "$owner" == "root" ]] && (( 8#$perm <= 8#644 ))
}

# exports 파일에 와일드카드(*) 단독 사용 여부 (0=있음, 1=없음)
_u40_wildcard_exists() {
    local f; f="$(_u40_exports)"
    [[ -f "$f" ]] || return 1
    # 디렉터리 뒤에 *(옵션) 형식에서 호스트 부분이 * 단독인 경우
    grep -qE '^[^#]+[[:space:]]\*[[:space:](,]?' "$f" 2>/dev/null && return 0
    grep -qE '^[^#]+[[:space:]]\*$' "$f" 2>/dev/null && return 0
    return 1
}

h_U_40_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_40_capture_state "$KISA_PHASE"
    fi

    # NFS_ALLOWED_NETWORKS 미지정 → NFS 사용하지 않는 환경, U-39 에서 비활성화 처리 → 양호
    if [[ -z "${NFS_ALLOWED_NETWORKS:-}" ]]; then
        printf '양호 — NFS_ALLOWED_NETWORKS 미지정, U-39 에서 NFS 비활성화 처리(취약점 해당없음)'
        return 0
    fi

    local f; f="$(_u40_exports)"

    # nfs-server 가 없으면 양호 (NFS 서비스 자체 없음)
    local nfs_state
    nfs_state="$(systemctl is-enabled nfs-server 2>/dev/null || true)"
    if [[ -z "$nfs_state" || "$nfs_state" == "not-found" ]]; then
        printf '양호 — nfs-server 미설치(취약점 해당없음)'
        return 0
    fi

    local issues=()

    # exports 파일 없음
    if [[ ! -f "$f" ]]; then
        issues+=("$f 파일 없음")
    else
        # 권한 확인
        if ! _u40_exports_perm_ok; then
            local p o
            p=$(stat -c '%a' "$f" 2>/dev/null)
            o=$(stat -c '%U' "$f" 2>/dev/null)
            issues+=("$f 소유자/권한 불량(${o}/${p}, root/644 이하 필요)")
        fi
        # 와일드카드 단독 사용
        if _u40_wildcard_exists; then
            issues+=("$f 에 와일드카드(*) 단독 사용 — 접근 통제 미흡")
        fi
    fi

    if (( ${#issues[@]} == 0 )); then
        printf '양호 — NFS exports 접근 통제 적정(허용: %s)' "${NFS_ALLOWED_NETWORKS}"
        return 0
    fi

    printf '취약 — %s' "${issues[*]}"
    return 1
}

h_U_40_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_40_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) NFS exports 이미 양호' ;;
            3) printf '(dry-run) 해당없음(NFS_ALLOWED_NETWORKS 미지정 또는 미설치)' ;;
            *) printf '(dry-run) exports 권한 644 + 와일드카드 확인·수정 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_40_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 NFS exports 접근 통제 적정'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — NFS_ALLOWED_NETWORKS 미지정 또는 nfs-server 미설치'; return 3; fi

    local f; f="$(_u40_exports)"
    local changed=0 manual_needed=0

    # exports 파일 없으면 최소한 생성
    if [[ ! -f "$f" ]]; then
        printf '# KISA U-40: NFS exports — %s\n' "${NFS_ALLOWED_NETWORKS}" | \
            atomic_write "$f" 0644 root root
        log_info "U-40: $f 파일 생성됨" >&2
        changed=1
    else
        backup_file "$f"

        # 권한 수정
        if ! _u40_exports_perm_ok; then
            chown root:root "$f"
            chmod 644 "$f"
            changed=1
        fi

        # 와일드카드 단독 사용 → NFS_ALLOWED_NETWORKS 의 첫 번째 네트워크로 자동 교체
        if _u40_wildcard_exists; then
            local first_net
            first_net="$(printf '%s' "$NFS_ALLOWED_NETWORKS" | cut -d',' -f1 | tr -d ' ')"
            local tmp; tmp="${KISA_TMP_DIR}/tmp/u40.$$.${RANDOM}"
            mkdir -p "${KISA_TMP_DIR}/tmp"
            # awk: 주석 아닌 라인의 첫 컬럼(디렉터리) 다음에 등장하는 ' *(...)' 또는 ' *' 단독 호스트를 first_net 으로 교체
            awk -v fn="$first_net" '
                /^[[:space:]]*#/ || /^[[:space:]]*$/ { print; next }
                {
                    # 첫 컬럼 = 디렉터리, 그 뒤 모든 토큰 = host(opt)... 형태
                    line = $0
                    # 디렉터리와 나머지를 분리 (탭/공백 모두 허용)
                    n = match(line, /[[:space:]]+/)
                    if (n == 0) { print; next }
                    dir = substr(line, 1, n-1)
                    rest = substr(line, n+RLENGTH)
                    # 와일드카드 단독: " * " or " *(opt)" or 단순 "*"
                    out_rest = ""
                    while (match(rest, /[^[:space:]]+/) > 0) {
                        host_with_opts = substr(rest, RSTART, RLENGTH)
                        rest = substr(rest, RSTART+RLENGTH)
                        # host_with_opts 분해: "host" 또는 "host(opt1,opt2)"
                        if (match(host_with_opts, /^\*(\(.*\))?$/) > 0) {
                            opts = substr(host_with_opts, 2)  # "(...)" or ""
                            host_with_opts = fn opts
                        }
                        out_rest = out_rest " " host_with_opts
                    }
                    print dir out_rest
                }
            ' "$f" > "$tmp"
            local om; om=$(stat -c '%a' "$f" 2>/dev/null || printf '644')
            mv -f "$tmp" "$f"
            chmod "$om" "$f" 2>/dev/null || true
            chown root:root "$f" 2>/dev/null || true
            command -v restorecon >/dev/null 2>&1 && restorecon "$f" 2>/dev/null || true
            log_info "U-40: $f 와일드카드(*) → ${first_net} 자동 교체 완료" >&2
            changed=1
        fi
    fi

    # exportfs 재적용
    if (( changed == 1 )) && command -v exportfs >/dev/null 2>&1; then
        exportfs -ra 2>/dev/null || log_warn "U-40: exportfs -ra 실패"
    fi

    # firewalld reload 큐
    if systemctl is-active firewalld >/dev/null 2>&1; then
        _queue_service_op reload firewalld
        _queue_rollback systemctl_reload firewalld
    fi

    if (( manual_needed == 1 )); then
        printf '수동 조치 필요 — exports 권한 644 적용 완료, 와일드카드 항목 수동 검토 필요(허용: %s)\n조치: /etc/exports 의 와일드카드(*) 단독 항목을 허용 네트워크로 교체' "${NFS_ALLOWED_NETWORKS}"
        return 2
    fi

    printf '조치 완료 — NFS exports 접근 통제 적용(허용: %s)' "${NFS_ALLOWED_NETWORKS}"
    return 0
}
