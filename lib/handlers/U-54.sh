#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-54: 암호화되지 않는 FTP 서비스 비활성화 (중요도: 중)
# KISA 가이드: 암호화되지 않은 FTP(vsftpd) 서비스 비활성화.
#
# Rocky 8/9/10: vsftpd 미설치 시 N/A.
#   FTP_MODE=disable (기본) → vsftpd disable+mask.
#   FTP_MODE=enable          → vsftpd unmask + enable + start + 보안 설정
#                              (anonymous_enable=NO, local_enable=YES, write_enable=NO).
#                              ⚠️ 평문 전송 — KISA 권고 위반. 사이트 정책 불가피한 경우만.
#   FTP_MODE=keep            → 서비스 상태 그대로, vsftpd.conf 의 anonymous_enable=NO 만 강제,
#                              return 2 (manual 안내).
#
# 롤백 전략: systemctl_state 큐잉 / vsftpd.conf restore_file

h_U_54_meta() {
    cat <<'JSON'
{
  "code": "U-54",
  "title": "암호화되지 않는 FTP 서비스 비활성화",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "암호화되지 않은 FTP 서비스를 비활성화함으로써 계정 및 중요 정보 유출 방지하기 위함",
  "threat": "암호화되지 않은 FTP 서비스를 사용할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 계정 및 중요 정보를 외부로 유출할 위험이 존재함",
  "criterion_good": "암호화되지 않은 FTP 서비스가 비활성화된 경우",
  "criterion_bad": "암호화되지 않은 FTP 서비스가 활성화된 경우",
  "action_method": "암호화되지 않은 FTP 서비스 중지 및 비활성화 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "암호화되지 않은 FTP 서비스 비활성화 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-54 (2026 ver.)"
  ]
}
JSON
}

_u_54_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: FTP root 계정 접근 차단 설정"
        echo
        echo "## vsftpd 패키지 설치 + 서비스 상태"
        rpm -q vsftpd 2>&1 || true
        echo "is-enabled vsftpd: $(systemctl is-enabled vsftpd 2>&1)"
        echo "is-active  vsftpd: $(systemctl is-active  vsftpd 2>&1)"
        echo
        local _cf
        if [[ -f /etc/vsftpd/vsftpd.conf ]]; then _cf=/etc/vsftpd/vsftpd.conf
        elif [[ -f /etc/vsftpd.conf ]]; then _cf=/etc/vsftpd.conf
        else _cf=""; fi
        echo "## vsftpd.conf root 차단 관련 키 (userlist_*, ftpusers, allow_anon_*)"
        if [[ -n "$_cf" ]]; then
            grep -niE '^[[:space:]]*(userlist_enable|userlist_deny|userlist_file|listen|local_enable|anonymous_enable|root|ftpd_banner|chroot_local_user|allow_anon_ssl)[[:space:]]*=' "$_cf" 2>&1 || echo "(관련 라인 없음)"
        else
            echo "(vsftpd.conf 없음)"
        fi
        echo
        echo "## /etc/vsftpd/ftpusers (root 라인 차단 여부)"
        if [[ -f /etc/vsftpd/ftpusers ]]; then
            grep -nE '^[[:space:]]*#?[[:space:]]*root[[:space:]]*$' /etc/vsftpd/ftpusers 2>&1 || echo "(root 라인 없음)"
        else
            echo "(/etc/vsftpd/ftpusers 없음)"
        fi
        echo
        echo "## /etc/vsftpd/user_list (root 라인 + userlist_deny 와 결합)"
        if [[ -f /etc/vsftpd/user_list ]]; then
            grep -nE '^[[:space:]]*#?[[:space:]]*root[[:space:]]*$' /etc/vsftpd/user_list 2>&1 || echo "(root 라인 없음)"
        else
            echo "(/etc/vsftpd/user_list 없음)"
        fi
    } | _evidence_capture "$label"
}


_u54_vsftpd_conf() {
    if [[ -f /etc/vsftpd/vsftpd.conf ]]; then
        printf '/etc/vsftpd/vsftpd.conf'
    else
        printf '/etc/vsftpd.conf'
    fi
}

_u54_vsftpd_installed() {
    rpm -q vsftpd >/dev/null 2>&1
}

_u54_vsftpd_active() {
    systemctl is-active vsftpd >/dev/null 2>&1
}

_u54_vsftpd_enabled() {
    local st; st="$(systemctl is-enabled vsftpd 2>/dev/null || printf 'disabled')"
    [[ "$st" == "enabled" ]]
}

h_U_54_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_54_capture_state "$KISA_PHASE"
    fi

    if ! _u54_vsftpd_installed; then
        printf '양호 — vsftpd 미설치(평문 FTP 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    local mode="${FTP_MODE:-disable}"

    if [[ "$mode" == "enable" ]]; then
        # FTP_MODE=enable: vsftpd active + enabled + 보안 설정 (anonymous_enable=NO 등) 적용
        local cf; cf="$(_u54_vsftpd_conf)"
        local anon_ok=0
        [[ -r "$cf" ]] && grep -qiE '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*NO' "$cf" && anon_ok=1
        if _u54_vsftpd_active && _u54_vsftpd_enabled && (( anon_ok == 1 )); then
            printf '양호 — vsftpd active + enabled + anonymous_enable=NO (FTP_MODE=enable, 보안 설정 적용됨)'
            return 0
        fi
        printf '취약 — FTP_MODE=enable 이지만 vsftpd 비활성/미활성화(disabled/masked) 또는 anonymous_enable 미설정'
        return 1
    fi

    if [[ "$mode" == "keep" ]]; then
        # FTP_MODE=keep: 서비스가 구동 중이어도 취약 판정 (암호화 미사용)
        if _u54_vsftpd_active || _u54_vsftpd_enabled; then
            local cf; cf="$(_u54_vsftpd_conf)"
            local anon_ok=0
            [[ -r "$cf" ]] && grep -qiE '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*NO' "$cf" && anon_ok=1
            if (( anon_ok == 0 )); then
                printf '취약 — vsftpd 구동 중, FTP_MODE=keep — anonymous_enable 미설정'
                return 1
            fi
            printf '취약 — vsftpd 구동 중, FTP_MODE=keep — anonymous_enable=NO 설정됨(평문 FTP 유지, 수동 확인 권장)'
            return 1
        fi
        printf '양호 — vsftpd 비활성 상태'
        return 0
    fi

    # FTP_MODE=disable (기본)
    if _u54_vsftpd_active || _u54_vsftpd_enabled; then
        printf '취약 — vsftpd 서비스 활성화됨 (암호화되지 않는 FTP 구동 중)'
        return 1
    fi

    local st; st="$(systemctl is-enabled vsftpd 2>/dev/null || printf 'unknown')"
    if [[ "$st" == "masked" ]]; then
        printf '양호 — vsftpd masked 상태'
        return 0
    fi

    printf '양호 — vsftpd 설치됨, 비활성화 상태'
    return 0
}

h_U_54_apply() {
    local mode="${FTP_MODE:-disable}"

    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u54_vsftpd_installed; then
            printf '(dry-run) vsftpd 미설치, 조치 불필요(N/A)'
            return 0
        fi
        case "$mode" in
            enable)  printf '(dry-run) vsftpd unmask + enable + start + 보안 설정 적용 예정' ;;
            keep)    printf '(dry-run) FTP_MODE=keep — anonymous_enable=NO 등 안전 설정 적용 예정' ;;
            *)       printf '(dry-run) vsftpd disable+mask 예정' ;;
        esac
        return 0
    fi

    if ! _u54_vsftpd_installed; then
        printf '해당없음 — vsftpd 미설치(평문 FTP 서비스 없음)'
        return 3
    fi

    local rc; h_U_54_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 양호 상태(조치 불필요)'
        return 0
    fi

    # FTP_MODE=enable: vsftpd 살리기 + 보안 설정
    if [[ "$mode" == "enable" ]]; then
        local cur_state
        cur_state="$(systemctl is-enabled vsftpd 2>/dev/null || printf 'disabled')"
        # rollback 큐: 원래 상태로 복원
        _queue_rollback systemctl_state "vsftpd:${cur_state}"

        # mask 풀기 + enable + start
        systemctl unmask vsftpd 2>/dev/null || true
        systemctl enable --now vsftpd 2>/dev/null || true

        # 보안 설정 강제 (anonymous_enable=NO, local_enable=YES, write_enable=NO)
        local cf; cf="$(_u54_vsftpd_conf)"
        if [[ -f "$cf" ]]; then
            backup_file "$cf"
            set_kv "$cf" 'anonymous_enable' 'anonymous_enable=NO'
            set_kv "$cf" 'local_enable'     'local_enable=YES'
            set_kv "$cf" 'write_enable'     'write_enable=NO'
            systemctl restart vsftpd >/dev/null 2>&1 || true
            _queue_rollback systemctl_restart vsftpd
        fi

        printf '조치 완료 — vsftpd unmask + enable + start, 보안 설정 적용 (anonymous_enable=NO/local_enable=YES/write_enable=NO)'
        return 0
    fi

    if [[ "$mode" == "keep" ]]; then
        local cf; cf="$(_u54_vsftpd_conf)"
        if [[ -f "$cf" ]]; then
            backup_file "$cf"
            set_kv "$cf" 'anonymous_enable' 'anonymous_enable=NO'
            set_kv "$cf" 'local_enable'     'local_enable=YES'
            _queue_service_op restart vsftpd
            _queue_rollback   systemctl_restart vsftpd
        fi
        printf '수동 조치 필요 — FTP_MODE=keep: anonymous_enable=NO 설정 완료, 평문 FTP 서비스 유지중\n조치: SFTP 전환 권고'
        return 2
    fi

    # FTP_MODE=disable (기본)
    local cur_state
    cur_state="$(systemctl is-enabled vsftpd 2>/dev/null || printf 'disabled')"
    if [[ "$cur_state" != "masked" ]]; then
        _queue_rollback systemctl_state "vsftpd:${cur_state}"
        systemctl disable --now vsftpd 2>/dev/null || true
        systemctl mask vsftpd 2>/dev/null || true
    fi

    printf '조치 완료 — vsftpd disable+mask'
    return 0
}
