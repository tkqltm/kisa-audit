#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-02: 비밀번호 관리정책 설정 (중요도: 상)
# KISA 가이드: minlen/dcredit/ucredit/lcredit/ocredit, PASS_MAX_DAYS, PASS_MIN_DAYS
#
# Rocky 8/9/10 공통 전략:
#   - /etc/security/pwquality.conf.d/kisa.conf (drop-in) 로 복잡성 정책 적용
#     → pwquality.conf.d 디렉터리는 RHEL 8+ 에서 지원, main 파일보다 drop-in 우선
#   - /etc/security/pwhistory.conf 로 remember=4, enforce_for_root 설정
#     (RHEL 8+ authselect 환경에서 pwhistory PAM 모듈이 이 파일을 읽음)
#   - /etc/login.defs 에서 PASS_MAX_DAYS / PASS_MIN_DAYS / PASS_WARN_AGE 설정
#
# Rocky 8 차이점:
#   - authselect 프로파일 'with-pwhistory' feature 가 없는 경우가 있음.
#     /etc/security/pwhistory.conf 는 RHEL 8.2+ 부터 지원 (pwhistory.conf drop-in 방식은
#     RHEL 9+; Rocky 8 에서는 파일 자체 직접 편집).
#
# 롤백 전략:
#   - backup_file 로 각 파일 백업 후 set_kv/atomic_write.
#   - 서비스 재시작 불필요(PAM/login.defs 는 다음 인증 시 반영).

h_U_02_meta() {
    cat <<'JSON'
{
  "code": "U-02",
  "title": "비밀번호 관리정책 설정",
  "severity": "상",
  "category": "계정 관리",
  "purpose": "사용자의 비밀번호 복잡성과 주기적 변경을 통해 시스템 보안을 강화하기 위함",
  "threat": "비밀번호 관련 정책이 설정되지 않을 경우, 비인가자의 각종 공격(무차별 대입 공격, 사전 대입 공격 등)에 의해 비밀번호가 노출될 위험이 존재함",
  "criterion_good": "비밀번호 관리 정책이 설정된 경우",
  "criterion_bad": "비밀번호 관리 정책이 설정되지 않은 경우",
  "action_method": "root 계정을 포함한 사용자 계정의 비밀번호를 영문, 숫자, 특수문자를 포함하여 최소 8자리 이상 및 최소 사용 기간 1일, 최대 사용 기간 90일, 최근 비밀번호 기억 4회 이상으로 설정",
  "action_impact": "비밀번호 변경 시 Web, WAS, DB 연동 구간에서 문제가 발생할 수 있으므로 연동 구간에 미칠 수 있는 영향을 고려하여 적용 필요",
  "method": [
    "비밀번호 관리 정책 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-02 (2026 ver.)"
  ]
}
JSON
}

_u_02_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 패스워드 복잡성 정책 (minlen/dcredit/ucredit/lcredit/ocredit)"
        echo
        echo "## /etc/login.defs PASS_MAX_DAYS / PASS_MIN_DAYS / PASS_MIN_LEN / PASS_WARN_AGE"
        grep -nE '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)[[:space:]]' /etc/login.defs 2>/dev/null \
            || echo "(/etc/login.defs 에 항목 없음)"
        echo
        echo "## /etc/security/pwquality.conf 핵심 값"
        if [[ -f /etc/security/pwquality.conf ]]; then
            grep -nE '^[[:space:]]*(minlen|dcredit|ucredit|lcredit|ocredit|minclass|maxrepeat|difok|enforce_for_root)' \
                /etc/security/pwquality.conf 2>/dev/null \
                || echo "(설정 없음 — 기본값 사용)"
        else
            echo "(/etc/security/pwquality.conf 없음)"
        fi
        echo
        echo "## /etc/security/pwquality.conf.d/*.conf"
        if [[ -d /etc/security/pwquality.conf.d ]]; then
            ls -l /etc/security/pwquality.conf.d/ 2>&1
            for _f in /etc/security/pwquality.conf.d/*.conf; do
                [[ -f "$_f" ]] || continue
                echo "### $_f"
                grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$_f" 2>/dev/null
            done
        else
            echo "(/etc/security/pwquality.conf.d 디렉터리 없음)"
        fi
        echo
        echo "## /etc/security/pwhistory.conf"
        if [[ -f /etc/security/pwhistory.conf ]]; then
            grep -nE '^[[:space:]]*(remember|enforce_for_root|retry)' /etc/security/pwhistory.conf 2>/dev/null \
                || echo "(설정 없음 — 기본값 사용)"
        else
            echo "(/etc/security/pwhistory.conf 없음)"
        fi
        echo
        echo "## /etc/pam.d/system-auth + password-auth 의 pam_pwquality / pam_pwhistory 라인"
        for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
            [[ -f "$_f" ]] || continue
            echo "### $_f"
            grep -nE 'pam_(pwquality|pwhistory|cracklib)' "$_f" 2>/dev/null \
                || echo "(pam_pwquality/pwhistory 라인 없음)"
        done
    } | _evidence_capture "$label"
}


_u02_login_defs()     { printf '/etc/login.defs'; }
_u02_pwquality_conf() { printf '/etc/security/pwquality.conf'; }
_u02_pwquality_dir()  { printf '/etc/security/pwquality.conf.d'; }
_u02_pwquality_drop() { printf '/etc/security/pwquality.conf.d/kisa.conf'; }
_u02_pwhistory()      { printf '/etc/security/pwhistory.conf'; }

# /etc/security/pwquality.conf.d/ 디렉터리가 존재하거나 생성 가능하면 drop-in 방식 사용
_u02_use_dropin() {
    local d; d="$(_u02_pwquality_dir)"
    [[ -d "$d" ]] || mkdir -p "$d" 2>/dev/null
    [[ -d "$d" ]]
}

# 현재 유효 minlen 값 반환 (drop-in > main 순)
_u02_current_minlen() {
    local v=""
    if [[ -f "$(_u02_pwquality_drop)" ]]; then
        v=$(awk -F'[= \t]+' '/^[[:space:]]*minlen/{print $2; exit}' "$(_u02_pwquality_drop)" 2>/dev/null)
    fi
    if [[ -z "$v" ]]; then
        v=$(awk -F'[= \t]+' '/^[[:space:]]*minlen/{print $2; exit}' "$(_u02_pwquality_conf)" 2>/dev/null)
    fi
    printf '%s' "${v:-0}"
}

# credit 값이 -1 이하인지 확인 (pwquality 기준)
_u02_credit_ok() {
    local key="$1" file="$2"
    local v
    v=$(awk -F'[= \t]+' -v k="$key" '$1==k{print $2; exit}' "$file" 2>/dev/null)
    [[ -n "$v" ]] && (( v <= -1 ))
}

h_U_02_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_02_capture_state "$KISA_PHASE"
    fi

    local ok=1
    local issues=()

    # --- login.defs ---
    local defs; defs="$(_u02_login_defs)"
    local max_days min_days
    max_days=$(awk '/^[[:space:]]*PASS_MAX_DAYS/{print $2; exit}' "$defs" 2>/dev/null)
    min_days=$(awk '/^[[:space:]]*PASS_MIN_DAYS/{print $2; exit}' "$defs" 2>/dev/null)

    if [[ -z "$max_days" ]] || (( max_days > ${PASSWORD_MAX_AGE:-90} || max_days <= 0 )); then
        issues+=("PASS_MAX_DAYS=${max_days:-미설정}(>${PASSWORD_MAX_AGE:-90})")
        ok=0
    fi
    if [[ -z "$min_days" ]] || (( min_days < ${PASSWORD_MIN_AGE:-1} )); then
        issues+=("PASS_MIN_DAYS=${min_days:-미설정}(<${PASSWORD_MIN_AGE:-1})")
        ok=0
    fi

    # --- pwquality: minlen, credits ---
    local qfile
    if [[ -f "$(_u02_pwquality_drop)" ]]; then
        qfile="$(_u02_pwquality_drop)"
    else
        qfile="$(_u02_pwquality_conf)"
    fi

    local minlen
    minlen=$(awk -F'[= \t]+' '/^[[:space:]]*minlen/{print $2; exit}' "$qfile" 2>/dev/null)
    if [[ -z "$minlen" ]] || (( minlen < ${PASSWORD_MIN_LEN:-8} )); then
        issues+=("minlen=${minlen:-미설정}(<${PASSWORD_MIN_LEN:-8})")
        ok=0
    fi

    for cred in dcredit ucredit lcredit ocredit; do
        if ! _u02_credit_ok "$cred" "$qfile"; then
            local cv
            cv=$(awk -F'[= \t]+' -v k="$cred" '$1==k{print $2; exit}' "$qfile" 2>/dev/null)
            issues+=("${cred}=${cv:-미설정}(≥0)")
            ok=0
        fi
    done

    # KISA 권고값: difok=4, maxrepeat=0
    local difok maxrepeat
    difok=$(awk -F'[= \t]+' '/^[[:space:]]*difok/{print $2; exit}' "$qfile" 2>/dev/null)
    maxrepeat=$(awk -F'[= \t]+' '/^[[:space:]]*maxrepeat/{print $2; exit}' "$qfile" 2>/dev/null)
    if [[ -z "$difok" ]] || (( difok < 4 )); then
        issues+=("difok=${difok:-미설정}(<4)")
        ok=0
    fi
    if [[ -z "$maxrepeat" ]]; then
        issues+=("maxrepeat=미설정")
        ok=0
    fi

    # pwhistory.conf: file = /etc/security/opasswd 명시 (KISA 권고)
    local pwhist; pwhist="$(_u02_pwhistory)"
    if [[ -f "$pwhist" ]]; then
        if ! grep -qE '^[[:space:]]*file[[:space:]]*=' "$pwhist"; then
            issues+=("pwhistory.file 미설정")
            ok=0
        fi
    fi

    if (( ok )); then
        printf '양호 — 비밀번호 정책 충족(PASS_MAX_DAYS=%s, MIN_DAYS=%s, minlen=%s, credits ok)' \
               "$max_days" "$min_days" "$minlen"
        return 0
    else
        printf '취약 — 미충족 항목: %s' "$(IFS=','; printf '%s' "${issues[*]}")"
        return 1
    fi
}

h_U_02_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) 예정: login.defs PASS_MAX_DAYS=%s/MIN_DAYS=%s/WARN_AGE=%s; pwquality minlen=%s dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1; pwhistory remember=4' \
               "${PASSWORD_MAX_AGE:-90}" "${PASSWORD_MIN_AGE:-1}" "${PASSWORD_WARN_AGE:-7}" "${PASSWORD_MIN_LEN:-8}"
        return 0
    fi

    local defs; defs="$(_u02_login_defs)"
    local pwhist; pwhist="$(_u02_pwhistory)"
    local max_age="${PASSWORD_MAX_AGE:-90}"
    local min_age="${PASSWORD_MIN_AGE:-1}"
    local warn_age="${PASSWORD_WARN_AGE:-7}"
    local min_len="${PASSWORD_MIN_LEN:-8}"

    # 1) login.defs
    backup_file "$defs"
    set_kv "$defs" 'PASS_MAX_DAYS' "PASS_MAX_DAYS\t${max_age}"
    set_kv "$defs" 'PASS_MIN_DAYS' "PASS_MIN_DAYS\t${min_age}"
    set_kv "$defs" 'PASS_WARN_AGE' "PASS_WARN_AGE\t${warn_age}"

    # 2) pwquality drop-in (또는 main)
    if _u02_use_dropin; then
        local drop; drop="$(_u02_pwquality_drop)"
        backup_file "$drop"
        atomic_write "$drop" 0644 root root <<EOF
# Managed by KISA U-02 (kisa-audit). Do not edit manually.
minlen = ${min_len}
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 4
maxrepeat = 0
enforce_for_root
EOF
    else
        local qconf; qconf="$(_u02_pwquality_conf)"
        backup_file "$qconf"
        set_kv "$qconf" 'minlen'          "minlen = ${min_len}"
        set_kv "$qconf" 'dcredit'         "dcredit = -1"
        set_kv "$qconf" 'ucredit'         "ucredit = -1"
        set_kv "$qconf" 'lcredit'         "lcredit = -1"
        set_kv "$qconf" 'ocredit'         "ocredit = -1"
        set_kv "$qconf" 'difok'            "difok = 4"
        set_kv "$qconf" 'maxrepeat'        "maxrepeat = 0"
        set_kv "$qconf" 'enforce_for_root' "enforce_for_root"
    fi

    # 3) pwhistory.conf (RHEL/Rocky 8+)
    backup_file "$pwhist"
    if [[ -f "$pwhist" ]]; then
        set_kv "$pwhist" 'remember'          "remember = 4"
        set_kv "$pwhist" 'file'              "file = /etc/security/opasswd"
        set_kv "$pwhist" 'enforce_for_root'  "enforce_for_root"
    else
        atomic_write "$pwhist" 0644 root root <<'EOF'
# Managed by KISA U-02 (kisa-audit). Do not edit manually.
enforce_for_root
remember = 4
file = /etc/security/opasswd
EOF
    fi

    printf '조치 완료 — 비밀번호 정책 적용(PASS_MAX_DAYS=%s, MIN_DAYS=%s, minlen=%s, dcredit/ucredit/lcredit/ocredit=-1, remember=4)' \
           "$max_age" "$min_age" "$min_len"
}
