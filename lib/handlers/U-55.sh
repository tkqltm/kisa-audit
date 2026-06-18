#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-55: FTP 계정 shell 제한 (중요도: 중)
# KISA 가이드: /etc/passwd 의 ftp 계정 shell 을 /sbin/nologin 으로 변경.
#
# Rocky 8/9/10: ftp 계정은 ftp 또는 vsftpd 패키지 설치 시 생성.
#   ftp 계정 없으면 N/A.
#   shell=/bin/false 또는 /sbin/nologin 이면 양호.
#
# 조치 전략:
#   1) ftp 계정 없음 → N/A
#   2) shell 이 /bin/false 또는 /sbin/nologin 이면 양호
#   3) usermod -s /sbin/nologin ftp 실행
#
# 롤백 전략: /etc/passwd backup_file (usermod 가 passwd 수정)

h_U_55_meta() {
    cat <<'JSON'
{
  "code": "U-55",
  "title": "FTP 계정 shell 제한",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "FTP 계정의 쉘을 통한 시스템 접근을 차단하기 위함",
  "threat": "FTP 기본 계정에 쉘이 부여될 경우, 비인가자가 해당 기본 계정으로 시스템에 접근할 위험이 존재함",
  "criterion_good": "FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우",
  "criterion_bad": "FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있지 않은 경우",
  "action_method": "- FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - FTP 서비스 사용 시 FTP 계정에 /bin/false 쉘 부여 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "FTP 기본 계정에 쉘 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-55 (2026 ver.)"
  ]
}
JSON
}

_u_55_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: getent passwd ftp"
        echo
        echo "# 결과: ftp 계정 정보"
        if _u55_ftp_exists; then
            getent passwd ftp 2>&1 || true
            echo
            echo "## ftp 계정 shell"
            _u55_ftp_shell
        else
            echo "(ftp 계정 없음 — vsftpd/anonymous-ftp 미사용)"
        fi
    } | _evidence_capture "$label"
}


_u55_ftp_shell() {
    getent passwd ftp 2>/dev/null | cut -d: -f7
}

_u55_ftp_exists() {
    getent passwd ftp >/dev/null 2>&1
}

_u55_is_ok() {
    local sh; sh="$(_u55_ftp_shell)"
    case "$sh" in
        /bin/false|/sbin/nologin|/usr/sbin/nologin) return 0 ;;
    esac
    return 1
}

h_U_55_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_55_capture_state "$KISA_PHASE"
    fi

    if ! _u55_ftp_exists; then
        printf '해당없음 — ftp 계정 없음'
        return 3
    fi

    local sh; sh="$(_u55_ftp_shell)"
    if _u55_is_ok; then
        printf '양호 — ftp 계정 shell=%s (로그인 차단)' "$sh"
        return 0
    fi

    printf '취약 — ftp 계정 shell=%s, 로그인 차단 미적용' "${sh:-<empty>}"
    return 1
}

h_U_55_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u55_ftp_exists; then
            printf '(dry-run) 해당없음 — ftp 계정 없음, 조치 불필요'
            return 0
        fi
        if _u55_is_ok; then
            printf '(dry-run) 양호 — 이미 로그인 차단 shell, 조치 불필요'
        else
            printf '(dry-run) usermod -s /sbin/nologin ftp 실행 예정'
        fi
        return 0
    fi

    if ! _u55_ftp_exists; then
        printf '해당없음 — ftp 계정 없음'
        return 3
    fi

    if _u55_is_ok; then
        printf '양호 — 이미 로그인 차단 shell (shell=%s)' "$(_u55_ftp_shell)"
        return 0
    fi

    local before; before="$(_u55_ftp_shell)"

    # /etc/passwd 백업 (usermod 가 수정)
    backup_file /etc/passwd
    backup_file /etc/shadow 2>/dev/null || true

    if usermod -s /sbin/nologin ftp 2>/dev/null; then
        local after; after="$(_u55_ftp_shell)"
        printf '조치 완료 — ftp 계정 shell 변경: %s → %s' "$before" "$after"
        return 0
    else
        restore_file /etc/passwd
        printf '조치 실패 — usermod 실패, 변경 원복 완료'
        return 1
    fi
}
