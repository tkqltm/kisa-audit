#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-13: 안전한 비밀번호 암호화 알고리즘 사용 (중요도: 중)
# KISA 가이드: SHA-256($5$) 또는 SHA-512($6$) 이상 알고리즘 사용
#
# Rocky 8/9/10 공통 전략:
#   - /etc/shadow 에서 계정 비밀번호 해시 앞의 식별자($1:MD5, $2:Blowfish, $5:SHA-256, $6:SHA-512) 확인
#   - /etc/login.defs 의 ENCRYPT_METHOD 확인
#   - /etc/pam.d/system-auth 의 pam_unix.so 옵션 확인 (sha256/sha512)
#   - 취약하면 login.defs ENCRYPT_METHOD 를 SHA512 으로 설정
#     (pam_unix.so 도 sha512 로 설정하되, authselect 관리 파일은 직접 수정 최소화)
#
# Rocky 8 차이점:
#   - /etc/pam.d/system-auth 가 authselect 심볼릭 링크. 직접 수정 시 authselect 와 불일치.
#   - login.defs 수정만으로 신규 비밀번호 설정 시 SHA512 적용됨. 기존 해시는 재설정 필요.
#
# Rocky 9/10 차이점:
#   - yescrypt($y$) 알고리즘이 기본값일 수 있음. $y$ 는 SHA-2 이상으로 양호 처리.
#
# 주의: 알고리즘 변경 후 기존 계정 비밀번호는 passwd 로 재설정해야 새 알고리즘 적용됨.
#
# 롤백 전략:
#   - restore_file /etc/login.defs
#   - (pam.d 수정 시) restore_file /etc/pam.d/system-auth

h_U_13_meta() {
    cat <<'JSON'
{
  "code": "U-13",
  "title": "안전한 비밀번호 암호화 알고리즘 사용",
  "severity": "중",
  "category": "계정 관리",
  "purpose": "안전한 비밀번호 암호화 알고리즘을 사용하여 사용자 계정정보를 보호하기 위함",
  "threat": "취약한 비밀번호 암호화 알고리즘을 사용할 경우, 노출된 계정에 대해 비인가자가 암호 복호화 공격을 통해 비밀번호를 획득할 위험이 존재함",
  "criterion_good": "SHA-2 이상의 안전한 비밀번호 암호화 알고리즘을 사용하는 경우",
  "criterion_bad": "취약한 비밀번호 암호화 알고리즘을 사용하는 경우",
  "action_method": "SHA-2 이상의 안전한 비밀번호 암호화 알고리즘 적용 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "안전한 비밀번호 암호화 알고리즘을 사용 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-13 (2026 ver.)"
  ]
}
JSON
}

_u_13_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 비밀번호 암호화 알고리즘 (SHA-2 이상)"
        echo
        echo "## /etc/login.defs ENCRYPT_METHOD"
        grep -nE '^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null || echo "(ENCRYPT_METHOD 라인 없음)"
        echo
        echo "## /etc/pam.d/system-auth + password-auth pam_unix 알고리즘 옵션"
        for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
            if [[ -f "$_f" ]]; then
                echo "### $_f"
                grep -nE 'pam_unix\.so' "$_f" 2>/dev/null || echo "(pam_unix.so 라인 없음)"
            fi
        done
        echo
        echo "## /etc/shadow 해시 알고리즘 분포 (식별자별 카운트)"
        if [[ -r /etc/shadow ]]; then
            awk -F: 'length($2) > 1 {
                if (substr($2,1,1) == "$") {
                    end = index(substr($2,2), "$")
                    if (end > 0) id = substr($2, 1, end+1)
                    else id = $2
                } else {
                    id = "(plain/locked)"
                }
                cnt[id]++
            } END { for (k in cnt) printf "  %-12s : %d\n", k, cnt[k] }' /etc/shadow 2>/dev/null \
                || echo "(shadow 분석 실패)"
        else
            echo "(/etc/shadow 읽기 권한 없음)"
        fi
        echo
        echo "## authselect 현재 프로파일 (Rocky 8/9 해당)"
        if command -v authselect >/dev/null 2>&1; then
            authselect current 2>&1 || true
        fi
    } | _evidence_capture "$label"
}


_u13_shadow()       { printf '/etc/shadow'; }
_u13_login_defs()   { printf '/etc/login.defs'; }
_u13_system_auth()  { printf '/etc/pam.d/system-auth'; }

# 안전한 해시 알고리즘 식별자인지 확인
# $5$ = SHA-256, $6$ = SHA-512, $y$ = yescrypt, $2b$ = bcrypt (모두 양호)
_u13_is_safe_hash_id() {
    local id="$1"
    case "$id" in
        '$5$'|'$6$'|'$y$'|'$2b$'|'$2a$') return 0 ;;
        *) return 1 ;;
    esac
}

# /etc/shadow 에서 취약 해시 알고리즘을 사용하는 계정 목록 반환 (계정:식별자)
_u13_vuln_hash_accounts() {
    local shadow_f; shadow_f="$(_u13_shadow)"
    [[ -r "$shadow_f" ]] || return 0
    while IFS=: read -r user hash _rest; do
        # 잠긴 계정(!,*), 빈 hash, !locked 는 건너뜀
        [[ -z "$hash" || "$hash" == "!" || "$hash" == "*" || "$hash" == "!!" ]] && continue
        [[ "$hash" == !* || "$hash" == *"!"* ]] && continue
        # 해시 식별자 추출
        local id
        if [[ "$hash" == '$'* ]]; then
            id=$(printf '%s' "$hash" | grep -oP '^\$[0-9a-z]+\$' | head -1)
        else
            id="plain"
        fi
        if ! _u13_is_safe_hash_id "$id"; then
            printf '%s:%s\n' "$user" "${id:-unknown}"
        fi
    done < "$shadow_f" 2>/dev/null
}

# /etc/login.defs 의 ENCRYPT_METHOD 값 반환
_u13_current_encrypt_method() {
    awk '/^[[:space:]]*ENCRYPT_METHOD[[:space:]]/{print toupper($2); exit}' \
        "$(_u13_login_defs)" 2>/dev/null
}

# pam_unix.so 에 sha256/sha512 옵션이 설정되어 있는가?
_u13_pam_unix_safe() {
    grep -qE 'pam_unix\.so.*\b(sha256|sha512|yescrypt)\b' "$(_u13_system_auth)" 2>/dev/null
}

h_U_13_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_13_capture_state "$KISA_PHASE"
    fi

    local shadow_f; shadow_f="$(_u13_shadow)"
    if [[ ! -r "$shadow_f" ]]; then
        printf '/etc/shadow 읽기 실패'
        return 2
    fi

    # 1) 기존 해시 알고리즘 점검
    local vuln_accounts
    vuln_accounts=$(_u13_vuln_hash_accounts)

    # 2) login.defs ENCRYPT_METHOD 점검
    local enc_method; enc_method="$(_u13_current_encrypt_method)"
    local defs_ok=0
    case "${enc_method:-}" in
        SHA256|SHA512|YESCRYPT) defs_ok=1 ;;
    esac

    if [[ -z "$vuln_accounts" ]] && (( defs_ok )); then
        printf '양호 — ENCRYPT_METHOD=%s, 기존 계정 해시 모두 SHA-2 이상' "${enc_method:-기본}"
        return 0
    fi

    local issues=()
    if [[ -n "$vuln_accounts" ]]; then
        local cnt; cnt=$(printf '%s\n' "$vuln_accounts" | grep -c '.')
        issues+=("취약해시계정 ${cnt}개")
    fi
    if (( ! defs_ok )); then
        issues+=("ENCRYPT_METHOD=${enc_method:-미설정}")
    fi

    printf '취약 — %s' "$(IFS=','; printf '%s' "${issues[*]}")"
    return 1
}

h_U_13_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) /etc/login.defs ENCRYPT_METHOD=SHA512 설정 예정; 기존 취약 해시 계정 비밀번호 재설정 안내 예정'
        return 0
    fi

    local defs; defs="$(_u13_login_defs)"
    local enc_method; enc_method="$(_u13_current_encrypt_method)"

    # login.defs 가 이미 SHA512 이면 스킵
    local defs_already_ok=0
    case "${enc_method:-}" in
        SHA256|SHA512|YESCRYPT) defs_already_ok=1 ;;
    esac

    if (( ! defs_already_ok )); then
        backup_file "$defs"
        set_kv "$defs" 'ENCRYPT_METHOD' 'ENCRYPT_METHOD SHA512'
    fi

    # pam_unix.so 에 sha512 옵션 추가 (authselect 가 관리하지 않는 경우에만)
    local sys_auth; sys_auth="$(_u13_system_auth)"
    if [[ -f "$sys_auth" ]] && ! _u13_pam_unix_safe; then
        # authselect 가 관리하는 심볼릭 링크인지 확인
        if [[ ! -L "$sys_auth" ]]; then
            backup_file "$sys_auth"
            local tmp; tmp="$KISA_TMP_DIR/tmp/u13.$$.$RANDOM"
            local om ou og
            om=$(stat -c '%a' "$sys_auth" 2>/dev/null)
            ou=$(stat -c '%u' "$sys_auth" 2>/dev/null)
            og=$(stat -c '%g' "$sys_auth" 2>/dev/null)
            awk '
                /pam_unix\.so/ {
                    if ($0 !~ /sha256|sha512|yescrypt/) {
                        sub(/pam_unix\.so/, "pam_unix.so sha512")
                    }
                }
                { print }
            ' "$sys_auth" > "$tmp"
            mv -f "$tmp" "$sys_auth"
            [[ -n "$om" ]] && chmod "$om" "$sys_auth" 2>/dev/null || true
            [[ -n "$ou" && -n "$og" ]] && chown "$ou:$og" "$sys_auth" 2>/dev/null || true
            command -v restorecon >/dev/null 2>&1 && restorecon "$sys_auth" 2>/dev/null || true
        fi
        # authselect 심볼릭 링크인 경우: login.defs 만 변경, PAM 은 authselect 가 관리
    fi

    # 취약 해시 계정 목록 안내
    local vuln_accounts
    vuln_accounts=$(_u13_vuln_hash_accounts)

    local result="조치 완료 — ENCRYPT_METHOD=SHA512 설정"
    if [[ -n "$vuln_accounts" ]]; then
        result="${result}; 기존 취약해시 계정 비밀번호 재설정 필요: $(printf '%s' "$vuln_accounts" | awk -F: '{printf "%s ",$1}')"
    fi

    printf '%s' "$result"
}
