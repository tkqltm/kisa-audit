#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-36: r 계열 서비스 비활성화 (중요도: 상)
# KISA 가이드: rsh, rlogin, rexec 등 r-command 서비스 비활성화.
#
# Rocky 8/9/10: rsh-server 패키지가 기본 미설치 → 대부분 N/A.
#   점검 대상:
#     - rpm -q rsh-server
#     - systemctl: rsh.service, rlogin.service, rexec.service (또는 .socket)
#     - xinetd: /etc/xinetd.d/{rsh,rlogin,rexec}
#     - /etc/hosts.equiv, ~/.rhosts (내용 있으면 경고)
#
# 조치 전략:
#   1) r-command 패키지 미설치 + 관련 서비스/소켓 없음 + hosts.equiv/.rhosts 없음 → N/A
#   2) 서비스 존재 시 disable+mask
#   3) xinetd 기반 파일 존재 시 disable=yes 로 수정
#   4) hosts.equiv/.rhosts 는 내용 비워야 하지만 자동조치는 manual 권고
#
# 롤백: _queue_rollback systemctl_state

h_U_36_meta() {
    cat <<'JSON'
{
  "code": "U-36",
  "title": "r 계열 서비스 비활성화",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "r-command 사용을 통한 원격 접속은 NET Backup 또는 클러스터링 등 용도로 사용되기도 하나, 인증 없이 관리자 원격 접속이 가능하여 이에 대한 보안 위협을 방지하기 위함",
  "threat": "rlogin, rsh, rexec 등의 r-command를 이용하여 원격에서 인증 절차 없이 터미널 접속, 쉘 명령어를 실행이 가능한 위험이 존재함",
  "criterion_good": "불필요한 r 계열 서비스가 비활성화된 경우",
  "criterion_bad": "불필요한 r 계열 서비스가 활성화된 경우",
  "action_method": "불필요한 r 계열 서비스 중지 및 비활성화 설정 ※ NET Backup 등 특별한 용도로 사용하지 않는다면 shell(514), login(513), exec(512) 서비스 중 지 ※ rlogin, rsh, rexec 서비스는 backup, 클러스터링 등의 용도로 종종 사용되고 있으므로 해당 서비 스 사용 유무를 확인하여 미사용시 서비스 중지 ※ /etc/hosts.equiv 또는 $HOME/.rhosts 파일을 통해 해당 서비스 사용 여부 확인 (파일이 존재 하지 않거나 해당 파일 내에 설정이 없다면 사용하지 않는 것으로 간주)",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "r-command 서비스 비활성화 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-36 (2026 ver.)"
  ]
}
JSON
}

_u_36_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: r 계열 서비스 (rlogin, rsh, rexec) 비활성화 여부"
        echo
        echo "## rsh-server 패키지 설치"
        rpm -q rsh-server rsh 2>&1 || true
        echo
        echo "## r 계열 systemd 단위"
        local _u
        for _u in rlogin.socket rsh.socket rexec.socket rlogin@.service rsh@.service rexec@.service; do
            printf '%-22s is-enabled=%s   is-active=%s\n' \
                "$_u" \
                "$(systemctl is-enabled "$_u" 2>&1)" \
                "$(systemctl is-active  "$_u" 2>&1)"
        done
        echo
        echo "## xinetd 기반 r-command 설정 (disable 라인)"
        local f
        for f in /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec; do
            if [[ -f "$f" ]]; then
                echo "### $f"
                grep -nE '^[[:space:]]*disable' "$f" 2>/dev/null || echo "(disable 라인 없음 — 활성화)"
            fi
        done
        echo
        echo "## /etc/hosts.equiv (인증 우회) — 활성 라인"
        if [[ -f /etc/hosts.equiv ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/hosts.equiv 2>/dev/null || echo "(활성 항목 없음)"
        else
            echo "(/etc/hosts.equiv 없음)"
        fi
        echo
        echo "## /root/.rhosts — 활성 라인"
        if [[ -f /root/.rhosts ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /root/.rhosts 2>/dev/null || echo "(활성 항목 없음)"
        else
            echo "(/root/.rhosts 없음)"
        fi
        echo
        echo "## TCP 513(rlogin)/514(rsh)/512(rexec) LISTEN 상태"
        if command -v ss >/dev/null 2>&1; then
            ss -tlnp 2>/dev/null | awk 'NR==1 || $4 ~ /:(512|513|514)$/' || true
        fi
    } | _evidence_capture "$label"
}


_u36_rcmd_svcs() {
    # r-command 관련 service/socket unit 목록
    systemctl list-units --all --type=service --type=socket 2>/dev/null \
        | awk '{print $1}' \
        | grep -iE '^(rsh|rlogin|rexec|r-|rlogins|rshell|rexecd)' \
        | grep -v '^$' || true
}

_u36_xinetd_files() {
    local d=/etc/xinetd.d
    [[ -d "$d" ]] || return 0
    find "$d" -maxdepth 1 -type f \( -name 'rsh' -o -name 'rlogin' -o -name 'rexec' \) 2>/dev/null || true
}

# xinetd 파일에서 disable=yes 가 없으면 활성으로 간주 (0=활성)
_u36_xinetd_file_active() {
    local f="$1"
    [[ -f "$f" ]] || return 1
    grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$f" && return 1
    return 0
}

_u36_rhosts_issue() {
    # /etc/hosts.equiv 또는 root/.rhosts 에 내용 있으면 출력
    local out=""
    if [[ -s /etc/hosts.equiv ]]; then out+="/etc/hosts.equiv 내용 있음; "; fi
    if [[ -s /root/.rhosts ]]; then out+="/root/.rhosts 내용 있음; "; fi
    printf '%s' "$out"
}

h_U_36_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_36_capture_state "$KISA_PHASE"
    fi

    local pkg_ok=0 svc_active="" xi_active="" rhosts_issue

    # 패키지
    rpm -q rsh-server >/dev/null 2>&1 && pkg_ok=1

    # systemd 서비스
    local s; s="$(_u36_rcmd_svcs)"
    [[ -n "$s" ]] && svc_active="$s"

    # xinetd
    local xf
    while IFS= read -r xf; do
        [[ -z "$xf" ]] && continue
        if _u36_xinetd_file_active "$xf"; then
            xi_active+="$xf "
        fi
    done < <(_u36_xinetd_files)

    # rhosts
    rhosts_issue="$(_u36_rhosts_issue)"

    if (( pkg_ok == 0 )) && [[ -z "$svc_active" ]] && [[ -z "$xi_active" ]] && [[ -z "$rhosts_issue" ]]; then
        printf '양호 — rsh-server 미설치, r 계열 서비스/rhosts 파일 없음(취약점 해당없음)'
        return 0
    fi

    local issues=()
    [[ -n "$svc_active" ]] && issues+=("서비스 활성: $svc_active")
    [[ -n "$xi_active" ]] && issues+=("xinetd 활성: $xi_active")
    [[ -n "$rhosts_issue" ]] && issues+=("$rhosts_issue")

    if (( ${#issues[@]} == 0 )); then
        printf '양호 — r 계열 서비스 비활성화, hosts.equiv/.rhosts 없음'
        return 0
    fi

    printf '취약 — %s' "${issues[*]}"
    return 1
}

h_U_36_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_36_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 이미 양호, 조치 불필요' ;;
            3) printf '(dry-run) rsh-server 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) r 계열 서비스 disable+mask + xinetd disable=yes 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_36_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 r 계열 서비스 비활성화 상태'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — rsh-server 미설치'; return 3; fi

    local changed=0

    # systemd 서비스 disable+mask
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
    done < <(_u36_rcmd_svcs)

    # xinetd 기반 disable=yes
    local xf
    while IFS= read -r xf; do
        [[ -z "$xf" ]] && continue
        if _u36_xinetd_file_active "$xf"; then
            backup_file "$xf"
            set_kv "$xf" 'disable' 'disable = yes'
            changed=1
        fi
    done < <(_u36_xinetd_files)

    # xinetd 재시작
    if (( changed == 1 )) && systemctl is-active xinetd >/dev/null 2>&1; then
        _queue_service_op restart xinetd
        _queue_rollback systemctl_restart xinetd
    fi

    # hosts.equiv / .rhosts 는 수동 조치 안내
    local ri; ri="$(_u36_rhosts_issue)"
    if [[ -n "$ri" ]]; then
        log_warn "U-36: $ri — /etc/hosts.equiv, /root/.rhosts 내용 수동 검토 후 삭제 권장"
    fi

    if (( changed == 0 )) && [[ -z "$ri" ]]; then
        printf '양호 — 이미 r 계열 서비스 비활성화'
        return 0
    fi

    if [[ -n "$ri" ]]; then
        printf '수동 조치 필요 — r 계열 서비스 disable+mask 완료; /etc/hosts.equiv, /root/.rhosts 내용 수동 검토 필요\n조치: hosts.equiv/.rhosts 활성 항목 검토 후 삭제'
        return 2
    fi

    printf '조치 완료 — r 계열 서비스 disable+mask + xinetd disable=yes 적용'
    return 0
}
