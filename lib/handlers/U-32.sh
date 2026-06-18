#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-32: 홈 디렉토리로 지정한 디렉토리의 존재 관리 (중요도: 중)
# KISA 가이드: /etc/passwd 에 설정된 홈 디렉터리가 실제 존재하는지 점검
#
# 점검 기준:
#   양호: 모든 계정의 홈 디렉터리가 실제 존재
#   취약: 홈 디렉터리가 존재하지 않는 계정 발견
#
# 조치 전략:
#   - 자동 조치 불가 (userdel 또는 mkdir 여부는 관리자 결정)
#   - apply 에서 목록 출력 후 manual 안내
#
# 점검 대상:
#   - 로그인 가능한 계정만 대상 (nologin/false/빈 shell 제외)
#   - 근거: nologin 시스템 계정(clevis, cockpit-ws, pegasus 등)은 홈 디렉터리가
#     없어도 로그인 불가이므로 실제 보안 위협 없음. KISA 가이드 원문도
#     실제 로그인 가능 사용자를 대상으로 함.
#
# Rocky 8/9/10 공통

h_U_32_meta() {
    cat <<'JSON'
{
  "code": "U-32",
  "title": "홈 디렉토리로 지정한 디렉토리의 존재 관리",
  "severity": "중",
  "category": "파일 및 디렉토리 관리",
  "purpose": "/home 디렉토리 이외의 사용자의 홈 디렉토리 존재 여부를 점검하여 비인가자가 시스템 명령어의 무단 사용을 방지하기 위함",
  "threat": "/etc/passwd 파일에 설정된 홈 디렉토리가 존재하지 않는 경우, 해당 계정으로 로그인 시 홈 디렉토리가 루트 디렉토리(/)로 할당되어 접근이 가능한 위험이 존재함",
  "criterion_good": "홈 디렉토리가 존재하지 않는 계정이 발견되지 않는 경우",
  "criterion_bad": "홈 디렉토리가 존재하지 않는 계정이 발견된 경우",
  "action_method": "홈 디렉토리가 존재하지 않는 계정에 홈 디렉토리 설정 또는 계정 제거하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "사용자 계정과 홈 디렉토리의 일치 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-32 (2026 ver.)"
  ]
}
JSON
}

_u_32_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/passwd 의 각 로그인 가능 계정에 대해 홈 디렉터리 존재 여부 확인"
        echo
        echo "# 결과: 홈 디렉터리 미존재 계정 + 조치 옵션"
        local _miss
        _miss=$(_u32_missing_homes 2>/dev/null || true)
        if [[ -z "$_miss" ]]; then
            echo "(없음 — 모든 로그인 가능 계정의 홈 디렉터리 존재)"
        else
            printf '%s\n' "$_miss" | while IFS=' ' read -r user uid homedir; do
                [[ -z "$user" ]] && continue
                echo "계정: $user (uid=$uid) / 홈: $homedir"
                echo "    [옵션1] 계정 삭제:    userdel $user"
                echo "    [옵션2] 홈 생성:      mkdir -p $homedir && chown $user: $homedir && chmod 700 $homedir"
                echo "    [옵션3] 홈 경로 변경: usermod -d /home/$user $user"
            done
        fi
    } | _evidence_capture "$label"
}


# (user, uid, homedir) 중 homedir 이 존재하지 않는 항목 목록
# nologin/false shell 을 가진 시스템 계정은 제외 (로그인 불가이므로 보안 위협 없음)
_u32_missing_homes() {
    while IFS=: read -r user _ uid _ _ homedir shell; do
        [[ -n "$homedir" ]] || continue
        # '/' 는 항상 존재하므로 skip
        [[ "$homedir" == "/" ]] && continue
        # 로그인 불가 shell 인 시스템 계정 제외
        case "$shell" in
            */nologin|*/false|/bin/false|/sbin/nologin|/usr/sbin/nologin|/usr/bin/false|'')
                continue
                ;;
        esac
        [[ -d "$homedir" ]] || printf '%s %s %s\n' "$user" "$uid" "$homedir"
    done < /etc/passwd
}

h_U_32_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_32_capture_state "$KISA_PHASE"
    fi

    local missing=()

    while IFS=' ' read -r user uid homedir; do
        missing+=("${user}(${homedir})")
    done < <(_u32_missing_homes)

    if [[ ${#missing[@]} -eq 0 ]]; then
        printf '양호 — 모든 로그인 가능 계정의 홈 디렉터리가 존재함'
        return 0
    fi

    printf '취약 — 홈 디렉터리 미존재 계정 %d개 (예: %s)' "${#missing[@]}" "${missing[0]}"
    return 1
}

h_U_32_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local cnt=0
        while IFS=' ' read -r _u _i _h; do (( cnt++ )); done < <(_u32_missing_homes)
        printf '(dry-run) 홈 디렉터리 미존재 계정 %d개 — 수동 조치 안내 출력 예정' "$cnt"
        return 0
    fi

    local missing_list=()
    while IFS=' ' read -r user uid homedir; do
        missing_list+=("$user $uid $homedir")
    done < <(_u32_missing_homes)

    if [[ ${#missing_list[@]} -eq 0 ]]; then
        printf '양호 — 이미 모든 로그인 가능 계정의 홈 디렉터리가 존재하여 조치 불필요'
        return 0
    fi

    # 상세 목록·조치 옵션은 evidence 영역(_u_32_capture_state)에 기록됨 — 콘솔엔 요약만.
    log_warn "U-32: 홈 디렉터리 미존재 계정 ${#missing_list[@]}개 — 목록·조치는 report.html evidence 참조 (관리자 결정 필요)"

    printf '수동 조치 필요 — 홈 디렉터리 미존재 계정 %d개\n조치: 계정 삭제(userdel) 또는 홈 생성(mkdir) 여부는 관리자 결정. 전체 목록은 아래 evidence 참조.' \
        "${#missing_list[@]}"
    return 2
}
