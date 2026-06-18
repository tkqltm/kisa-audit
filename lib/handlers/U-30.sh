#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-30: UMASK 설정 관리 (중요도: 중)
# KISA 가이드: 시스템 UMASK 값이 022 이상 설정 여부 점검·조치
#
# 점검 기준:
#   양호: UMASK 값이 022 이상 (022, 027, 077 등)
#   취약: UMASK 값이 022 미만
#
# 점검·조치 대상 파일:
#   /etc/profile       — umask 022
#   /etc/bashrc        — umask 022
#   /etc/csh.cshrc     — umask 022 (csh/tcsh 설치 시)
#   /etc/csh.login     — umask 022 (csh/tcsh 설치 시)
#   /etc/login.defs    — UMASK 022
#
# 환경변수: UMASK_VALUE (기본 022)
#
# 조치 전략:
#   - set_kv 로 각 파일의 umask/UMASK 라인을 대상값으로 교체 (없으면 append)
#   - /etc/csh.cshrc, /etc/csh.login 미존재 시 skip (Rocky에서 csh 기본 미설치)
#   - idempotent
#
# Rocky 8/9/10 공통

h_U_30_meta() {
    cat <<'JSON'
{
  "code": "U-30",
  "title": "UMASK 설정 관리",
  "severity": "중",
  "category": "파일 및 디렉토리 관리",
  "purpose": "잘못 설정된 UMASK 값으로 인해 신규 파일에 대한 권한이 과도하게 부여되는 것을 방지하기 위함",
  "threat": "잘못 설정된 UMASK로 인해 파일 및 디렉터리 생성 시 과도한 권한이 부여되어 무단 액세스 및 데이터 유출의 위험이 존재함",
  "criterion_good": "UMASK 값이 022 이상으로 설정된 경우",
  "criterion_bad": "UMASK 값이 022 미만으로 설정된 경우",
  "action_method": "설정 파일에 UMASK 값을 022로 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "시스템 UMASK 값이 022 이상 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-30 (2026 ver.)"
  ]
}
JSON
}

_u_30_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 시스템 UMASK 022 이상 설정 여부"
        echo
        echo "## /etc/profile UMASK 라인"
        grep -nE '^[[:space:]]*umask' /etc/profile 2>/dev/null || echo "(/etc/profile에 umask 없음)"
        echo
        echo "## /etc/bashrc UMASK 라인"
        grep -nE '^[[:space:]]*umask' /etc/bashrc 2>/dev/null || echo "(/etc/bashrc에 umask 없음)"
        echo
        echo "## /etc/csh.cshrc, /etc/csh.login UMASK 라인"
        for _f in /etc/csh.cshrc /etc/csh.login; do
            [[ -f "$_f" ]] || continue
            echo "### $_f"
            grep -nE '^[[:space:]]*umask' "$_f" 2>/dev/null || echo "(umask 없음)"
        done
        echo
        echo "## /etc/login.defs UMASK 항목"
        grep -nE '^[[:space:]]*UMASK' /etc/login.defs 2>/dev/null || echo "(UMASK 없음)"
        echo
        echo "## /etc/profile.d/*.sh umask 라인"
        if [[ -d /etc/profile.d ]]; then
            grep -rnE '^[[:space:]]*umask' /etc/profile.d/ 2>/dev/null || echo "(umask 없음)"
        fi
        echo
        echo "## 현재 셸 effective umask"
        umask 2>&1 || true
    } | _evidence_capture "$label"
}


_u30_target_value() { printf '%s' "${UMASK_VALUE:-022}"; }

# umask 값이 022 이상인지 확인 (숫자가 클수록 더 엄격)
# umask 022 = 권한 755/644 → 안전. 002 = 775/664 → 취약.
# 022 이상 = 022, 027, 077 등. 비교: 10진수로 변환하여 22 이상이면 양호.
_u30_is_strict_enough() {
    local val="$1"
    # 8진수 string 을 10진수로 변환
    local dec
    dec=$(printf '%d\n' "0${val}" 2>/dev/null || printf '0')
    (( dec >= 18 ))  # 022(8) = 18(10)
}

# 파일에서 실효 umask 값 추출
_u30_read_umask_from_file() {
    local f="$1"
    [[ -f "$f" ]] || return 1
    # bash/sh 스타일: umask 022 또는 umask=022
    local v
    v=$(grep -iE '^[[:space:]]*(umask)[[:space:]=]+[0-7]+' "$f" 2>/dev/null \
        | grep -v '^[[:space:]]*#' | tail -1 \
        | grep -oE '[0-7]{3,4}' | tail -1)
    [[ -n "$v" ]] && printf '%s' "$v"
}

h_U_30_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_30_capture_state "$KISA_PHASE"
    fi

    local target; target="$(_u30_target_value)"
    local issues=0 checked=0

    local -a check_files=(/etc/profile /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/login.defs)
    local f
    for f in "${check_files[@]}"; do
        [[ -f "$f" ]] || continue
        (( checked++ ))

        local val; val="$(_u30_read_umask_from_file "$f")"
        if [[ -z "$val" ]]; then
            # umask 미설정 → 취약 (기본값에 의존하므로)
            (( issues++ ))
            continue
        fi
        _u30_is_strict_enough "$val" || (( issues++ ))
    done

    if (( checked == 0 )); then
        printf '해당없음 — umask 설정 파일 없음'
        return 3
    fi

    if (( issues == 0 )); then
        printf '양호 — 모든 umask 설정이 %s 이상' "$target"
        return 0
    fi

    printf '취약 — umask 설정 미흡 파일 %d개 (목표: %s 이상)' "$issues" "$target"
    return 1
}

h_U_30_apply() {
    local target; target="$(_u30_target_value)"

    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) umask=%s 설정 예정' "$target"
        return 0
    fi

    local fixed=0 skipped=0

    # 1) /etc/profile
    local f=/etc/profile
    if [[ -f "$f" ]]; then
        backup_file "$f"
        set_kv "$f" 'umask' "umask ${target}"
        (( fixed++ ))
    fi

    # 2) /etc/bashrc
    f=/etc/bashrc
    if [[ -f "$f" ]]; then
        backup_file "$f"
        set_kv "$f" 'umask' "umask ${target}"
        (( fixed++ ))
    fi

    # 3) /etc/csh.cshrc (csh/tcsh 설치 시만)
    f=/etc/csh.cshrc
    if [[ -f "$f" ]]; then
        backup_file "$f"
        set_kv "$f" 'umask' "umask ${target}"
        (( fixed++ ))
    else
        (( skipped++ ))
    fi

    # 4) /etc/csh.login (csh/tcsh 설치 시만)
    f=/etc/csh.login
    if [[ -f "$f" ]]; then
        backup_file "$f"
        set_kv "$f" 'umask' "umask ${target}"
        (( fixed++ ))
    else
        (( skipped++ ))
    fi

    # 5) /etc/login.defs — UMASK 대문자
    f=/etc/login.defs
    if [[ -f "$f" ]]; then
        backup_file "$f"
        set_kv "$f" 'UMASK' "UMASK\t${target}"
        (( fixed++ ))
    fi

    # 6) vsftpd — local_umask (KISA U-30 권고)
    f=/etc/vsftpd/vsftpd.conf
    if [[ -f "$f" ]]; then
        backup_file "$f"
        set_kv "$f" 'local_umask' "local_umask=${target}"
        systemctl is-active vsftpd >/dev/null 2>&1 && _queue_service_op restart vsftpd
        (( fixed++ ))
    fi

    # 7) proftpd — Umask (KISA U-30 권고)
    f=/etc/proftpd.conf
    if [[ ! -f "$f" ]] && [[ -f /etc/proftpd/proftpd.conf ]]; then
        f=/etc/proftpd/proftpd.conf
    fi
    if [[ -f "$f" ]]; then
        backup_file "$f"
        set_kv "$f" 'Umask' "Umask ${target}"
        systemctl is-active proftpd >/dev/null 2>&1 && _queue_service_op restart proftpd
        (( fixed++ ))
    fi

    printf '조치 완료 — umask %s 설정 %d개 파일 (skip %d개 — 파일 없음)' "$target" "$fixed" "$skipped"
    return 0
}
