#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-14: root 홈·패스 디렉터리 권한 및 패스 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: root 계정의 PATH 환경변수에 "."(현재 디렉터리)이 포함되는지 여부
# 판단 기준:
#   양호: PATH 환경변수에 "."이 맨 앞이나 중간에 포함되지 않은 경우
#   취약: PATH 환경변수에 "."이 맨 앞이나 중간에 포함된 경우
#
# 조치 전략:
#   - PATH에 "." 포함 여부: /etc/profile, /root/.bash_profile, /root/.bashrc, /root/.profile 파일 점검
#   - PATH 마지막(끝)의 "." 은 KISA 기준상 양호 (맨 앞·중간만 취약)
#   - 취약 파일에서 ":." ".:." ".:" 패턴을 제거하거나 주석 처리
#   - apply 후 환경변수 재소싱은 현재 프로세스에 적용 불가 → 관리자 재로그인 안내
#
# 롤백 전략:
#   - backup_file 으로 각 파일 백업 → restore_file 로 원복
#
# Rocky 8/9/10 특이사항:
#   - bash 기본 셸. /etc/bashrc, /etc/profile.d/*.sh 도 PATH 설정 가능하나
#     공식 KISA 점검 대상 파일만 검사 (4개 파일 + /etc/profile)

h_U_14_meta() {
    cat <<'JSON'
{
  "code": "U-14",
  "title": "root 홈, 패스 디렉터리 권한 및 패스 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "비인가자가 불법적으로 생성한 디렉터리 및 명령어를 우선으로 실행되지 않도록 설정하기 위함",
  "threat": "root 계정의 PATH 환경변수에 정상적인 관리자 명령어(ls, mv, cp 등)의 디렉터리 경로보다 현재 디렉터리를 지칭하는 “.” 표시가 우선하면 현재 디렉터리에 변조된 명령어를 삽입하여 관리자 명령어 입력 시 악의적인 기능이 실행될 수 있는 위험이 존재함",
  "criterion_good": "PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우",
  "criterion_bad": "PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함된 경우",
  "action_method": "root 계정의 환경설정 파일(/.profile, /.bashrc 등)과 시스템 환경설정 파일(/etc/profile 등)에 설정된 PATH 환경변수에서 현재 디렉터리를 나타내는 “.”을 PATH 환경변수의 마지막으로 이동하도록 설정 ※ /etc/profile 파일, root 계정, 일반 사용자 계정의 환경설정 파일을 순차적으로 검색하여 확인",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "root 계정의 PATH 환경변수에 “.”(마침표)이 포함 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-14 (2026 ver.)"
  ]
}
JSON
}

_u_14_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: root PATH 환경변수에 \".\" 포함 여부"
        echo
        echo "## root 셸의 PATH 값 (env)"
        env -i HOME=/root bash -lc 'echo "PATH=$PATH"' 2>&1 || true
        echo
        echo "## /etc/profile + /etc/profile.d 의 PATH 라인"
        grep -nE '^[[:space:]]*(export[[:space:]]+)?PATH=' /etc/profile 2>/dev/null || echo "(/etc/profile 에 PATH 라인 없음)"
        if [[ -d /etc/profile.d ]]; then
            grep -rnE '^[[:space:]]*(export[[:space:]]+)?PATH=' /etc/profile.d/ 2>/dev/null || echo "(/etc/profile.d 에 PATH 라인 없음)"
        fi
        echo
        echo "## /etc/bashrc 의 PATH 라인"
        grep -nE '^[[:space:]]*(export[[:space:]]+)?PATH=' /etc/bashrc 2>/dev/null || echo "(/etc/bashrc 에 PATH 라인 없음)"
        echo
        echo "## /root/{.bash_profile,.bashrc,.profile} 의 PATH 라인"
        for _f in /root/.bash_profile /root/.bashrc /root/.profile; do
            if [[ -f "$_f" ]]; then
                echo "### $_f"
                grep -nE '^[[:space:]]*(export[[:space:]]+)?PATH=' "$_f" 2>/dev/null || echo "(PATH 라인 없음)"
            else
                echo "### $_f (없음)"
            fi
        done
        echo
        echo "## \".\" 포함 패턴 검사 결과 (=., :., .:)"
        for _f in /etc/profile /root/.bash_profile /root/.bashrc /root/.profile; do
            [[ -f "$_f" ]] || continue
            grep -nE '^[[:space:]]*(export[[:space:]]+)?PATH=(\.(:|$)|.*:\.:.*)' "$_f" 2>/dev/null \
                && printf '  → %s : 취약 패턴 검출\n' "$_f"
        done
    } | _evidence_capture "$label"
}


# 점검 대상 파일 목록
_u14_target_files() {
    printf '%s\n' \
        '/etc/profile' \
        '/root/.bash_profile' \
        '/root/.bashrc' \
        '/root/.profile'
}

# PATH 설정 라인에서 "." 포함 여부 검사
# 반환: "취약파일:패턴" 목록을 stdout 출력, 취약 없으면 출력 없음
_u14_find_vuln_files() {
    local f
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        # PATH=...에서 .(콜론 구분자로) 또는 PATH 앞에 "." 가 있는 경우
        # 패턴: ^PATH=...에서 :. 또는 .: 또는 =. 로 시작하는 경우
        if grep -qE '^[[:space:]]*(export[[:space:]]+)?PATH=(\.(:|$)|.*:\.:.*)' "$f" 2>/dev/null; then
            local line
            line=$(grep -nE '^[[:space:]]*(export[[:space:]]+)?PATH=(\.(:|$)|.*:\.:.*)' "$f" 2>/dev/null | head -5)
            printf '%s: %s\n' "$f" "$line"
        fi
    done < <(_u14_target_files)
}

h_U_14_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_14_capture_state "$KISA_PHASE"
    fi

    local vuln_list
    vuln_list=$(_u14_find_vuln_files)

    if [[ -z "$vuln_list" ]]; then
        printf '양호 — root PATH 환경변수에 "." 미포함 (점검 대상 4개 파일)'
        return 0
    else
        printf '취약 — PATH에 "." 포함 파일 검출: %s' "$(printf '%s' "$vuln_list" | head -1)"
        return 1
    fi
}

h_U_14_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local vuln_list; vuln_list=$(_u14_find_vuln_files)
        if [[ -z "$vuln_list" ]]; then
            printf '(dry-run) 양호 — 취약 없음, 변경 불필요'
        else
            printf '(dry-run) PATH에서 "." 제거 예정 파일: %s' "$(printf '%s' "$vuln_list" | cut -d: -f1 | sort -u | tr '\n' ' ')"
        fi
        return 0
    fi

    local vuln_list; vuln_list=$(_u14_find_vuln_files)
    if [[ -z "$vuln_list" ]]; then
        printf '양호 — 이미 PATH에 "." 미포함, 조치 불필요'
        return 0
    fi

    local changed=()
    local f
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        # grep 으로 취약 라인 존재 확인
        if ! grep -qE '^[[:space:]]*(export[[:space:]]+)?PATH=(\.(:|$)|.*:\.:.*)' "$f" 2>/dev/null; then
            continue
        fi

        backup_file "$f"
        local tmp; tmp="$KISA_TMP_DIR/tmp/u14.$$.$RANDOM"
        mkdir -p "$KISA_TMP_DIR/tmp"

        local om ou og
        om=$(stat -c '%a' "$f" 2>/dev/null || true)
        ou=$(stat -c '%u' "$f" 2>/dev/null || true)
        og=$(stat -c '%g' "$f" 2>/dev/null || true)

        # PATH 라인에서 "." 제거:
        #   =. → =  (마침표로만 시작하는 경우 비워둠 → /usr/... 앞에 붙는 것 고려)
        #   .:  → (앞 마침표 제거)
        #   :.  → (뒤 마침표 제거)
        #   :.  끝에서도 제거
        awk '
        /^[[:space:]]*(export[[:space:]]+)?PATH=/ {
            # Remove leading .:  or  =.  patterns
            line = $0
            # Remove =./ only if standalone dot (not ./foo)
            # Pattern: remove standalone . entries from PATH
            # Split on = to get value part
            if (match(line, /PATH=/)) {
                prefix = substr(line, 1, RSTART + RLENGTH - 1)
                pathval = substr(line, RSTART + RLENGTH)
                # Remove trailing newline context
                # Replace patterns:  :.  or  .:  (standalone dot)
                # "." alone between colons or at start/end
                gsub(/(^|:)\.($|:)/, ":", pathval)  # remove standalone .
                gsub(/:\.($|:)/, ":", pathval)       # edge case
                gsub(/^\.?:/, "", pathval)           # remove leading .:
                gsub(/:$/, "", pathval)              # remove trailing colon artifact
                print prefix pathval
            } else {
                print
            }
            next
        }
        { print }
        ' "$f" > "$tmp"

        mv -f "$tmp" "$f"
        [[ -n "$om" ]] && chmod "$om" "$f" 2>/dev/null || true
        [[ -n "$ou" && -n "$og" ]] && chown "${ou}:${og}" "$f" 2>/dev/null || true
        command -v restorecon >/dev/null 2>&1 && restorecon "$f" 2>/dev/null || true
        changed+=("$f")
    done < <(_u14_target_files)

    if [[ ${#changed[@]} -eq 0 ]]; then
        printf '양호 — 이미 취약 파일 없음, 변경 불필요'
        return 0
    fi

    printf '조치 완료 — PATH에서 "." 제거: %s\n조치: 관리자 재로그인 후 적용 확인 필요' \
        "$(IFS=','; printf '%s' "${changed[*]}")"
    return 0
}
