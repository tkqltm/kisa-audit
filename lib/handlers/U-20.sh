#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-20: /etc/(x)inetd.conf 파일 소유자 및 권한 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: /etc/inetd.conf, /etc/xinetd.conf, /etc/xinetd.d/ 파일 권한 적절성
# 판단 기준:
#   양호: 소유자 root, 권한 600 이하 (group/other 에 어떤 권한도 없음)
#   취약: 소유자 root 아님, 또는 권한 600 초과
#   해당없음: inetd, xinetd 관련 파일이 모두 미존재 시 (return 3)
#
# 조치 전략 (자동, 파일 존재 시):
#   1) backup_file
#   2) chown root:root
#   3) chmod 600
#   4) restorecon
#
# Rocky 8/9/10 특이사항:
#   - inetd, xinetd 기본 미설치 → 파일 부재 시 해당없음(return 3)
#   - xinetd 패키지 설치된 경우 /etc/xinetd.conf, /etc/xinetd.d/ 존재 가능
#
# 롤백 전략:
#   - backup_file 기록으로 restore_file 자동 원복

h_U_20_meta() {
    cat <<'JSON'
{
  "code": "U-20",
  "title": "/etc/(x)inetd.conf 파일 소유자 및 권한 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "/etc/(x)inetd.conf 파일을 관리자만 제어하여 비인가자들의 임의적인 파일 변조를 방지하기 위함",
  "threat": "/etc/(x)inetd.conf 파일에 소유자 외 쓰기 권한이 부여된 경우, 일반 사용자 권한으로 해당 파일에 등록된 서비스를 변조하거나 악의적인 프로그램(서비스)을 등록할 수 있는 위험이 존재함",
  "criterion_good": "/etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 600 이하인 경우",
  "criterion_bad": "/etc/(x)inetd.conf 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우",
  "action_method": "/etc/(x)inetd.conf 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "/etc/(x)inetd.conf 파일 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-20 (2026 ver.)"
  ]
}
JSON
}

_u_20_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/(x)inetd.conf 소유자(root) + 권한(600 이하) 검증"
        echo
        echo "## xinetd 패키지 설치 + 서비스 상태"
        rpm -q xinetd 2>&1 || true
        echo "is-enabled xinetd: $(systemctl is-enabled xinetd 2>&1)"
        echo "is-active  xinetd: $(systemctl is-active  xinetd 2>&1)"
        echo
        echo "## /etc/inetd.conf"
        if [[ -f /etc/inetd.conf ]]; then
            ls -l /etc/inetd.conf 2>&1 || true
        else
            echo "(/etc/inetd.conf 없음)"
        fi
        echo
        echo "## /etc/xinetd.conf"
        if [[ -f /etc/xinetd.conf ]]; then
            ls -l /etc/xinetd.conf 2>&1 || true
        else
            echo "(/etc/xinetd.conf 없음)"
        fi
        echo
        echo "## /etc/xinetd.d 디렉터리 + 파일 권한"
        if [[ -d /etc/xinetd.d ]]; then
            ls -ld /etc/xinetd.d 2>&1 || true
            ls -l  /etc/xinetd.d/ 2>&1 | head -30 || true
        else
            echo "(/etc/xinetd.d 디렉터리 없음)"
        fi
        echo
        echo "## 비-root 소유 또는 group/other 권한 보유 파일"
        for _f in /etc/inetd.conf /etc/xinetd.conf; do
            [[ -f "$_f" ]] || continue
            find "$_f" -not -uid 0 -o -perm /077 2>/dev/null | head -5
        done
    } | _evidence_capture "$label"
}


_u20_inetd_path()  { printf '/etc/inetd.conf'; }
_u20_xinetd_path() { printf '/etc/xinetd.conf'; }
_u20_xinetd_dir()  { printf '/etc/xinetd.d'; }

# 600 이하: group/other 에 어떤 비트도 없음
# mode & 0077 == 0
_u20_perm_ok() {
    local mode="$1"
    local m; m=$(printf '%d' "0${mode}" 2>/dev/null || printf '9999')
    (( (m & 077) == 0 ))
}

# 존재하는 대상 파일 목록 반환
_u20_existing_targets() {
    local inetd;  inetd="$(_u20_inetd_path)"
    local xinetd; xinetd="$(_u20_xinetd_path)"
    local xdir;   xdir="$(_u20_xinetd_dir)"

    [[ -f "$inetd" ]]  && printf '%s\n' "$inetd"
    [[ -f "$xinetd" ]] && printf '%s\n' "$xinetd"
    if [[ -d "$xdir" ]]; then
        find "$xdir" -maxdepth 1 -type f 2>/dev/null
    fi
}

h_U_20_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_20_capture_state "$KISA_PHASE"
    fi

    local targets
    targets=$(_u20_existing_targets)

    if [[ -z "$targets" ]]; then
        printf '양호 — inetd/xinetd 미설치로 점검 대상 파일 없음'
        return 0
    fi

    local issues=()
    local f owner mode
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        owner=$(stat -c '%U' "$f" 2>/dev/null)
        mode=$(stat -c '%a' "$f" 2>/dev/null)
        [[ "$owner" != "root" ]] && issues+=("${f}:소유자=${owner}")
        _u20_perm_ok "$mode" || issues+=("${f}:권한=${mode}")
    done <<< "$targets"

    if [[ ${#issues[@]} -eq 0 ]]; then
        local flist; flist=$(printf '%s' "$targets" | tr '\n' ' ')
        printf '양호 — 점검 대상 파일 소유자 root + 권한 600 이하: %s' "$flist"
        return 0
    fi

    printf '취약 — 소유자/권한 부적절: %s' "$(IFS='; '; printf '%s' "${issues[*]}")"
    return 1
}

h_U_20_apply() {
    local targets
    targets=$(_u20_existing_targets)

    if [[ "${1:-}" == "--dry-run" ]]; then
        if [[ -z "$targets" ]]; then
            printf '(dry-run) inetd/xinetd 관련 파일 미존재 — 해당없음'
            return 0
        fi
        printf '(dry-run) 존재 파일에 chown root:root && chmod 600 적용 예정: %s' \
            "$(printf '%s' "$targets" | tr '\n' ' ')"
        return 0
    fi

    if [[ -z "$targets" ]]; then
        printf '해당없음 — inetd/xinetd 관련 파일 미존재'
        return 3
    fi

    local fixed=0 skipped=0
    local f owner mode
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        owner=$(stat -c '%U' "$f" 2>/dev/null)
        mode=$(stat -c '%a' "$f" 2>/dev/null)

        if [[ "$owner" == "root" ]] && _u20_perm_ok "$mode"; then
            (( skipped++ ))
            continue
        fi

        backup_file "$f"
        [[ "$owner" != "root" ]] && chown root:root "$f"
        _u20_perm_ok "$mode" || chmod 600 "$f"
        command -v restorecon >/dev/null 2>&1 && restorecon "$f" 2>/dev/null || true
        (( fixed++ ))
    done <<< "$targets"

    printf '조치 완료 — (x)inetd 설정 파일 chown root:root + chmod 600: %s건 수정, %s건 이미 양호' "$fixed" "$skipped"
    return 0
}
