#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-33: 숨겨진 파일 및 디렉토리 검색 및 제거 (중요도: 하)
# KISA 가이드: 숨겨진 파일·디렉터리 중 의심스러운 항목 탐지
#
# 점검 기준:
#   양호: 운영 목적 정상 숨김 파일 외 의심 파일·디렉터리 없음
#   취약: 불필요하거나 의심스러운 숨겨진 파일·디렉터리 존재
#
# 의심 파일 기준:
#   - /tmp, /var/tmp, /dev/shm 내 숨겨진 파일·디렉터리
#   - 이름이 '..', '... ', '.. ' (공백 포함) 등 이상한 이름
#   - 실행 권한 있는 숨김 파일 (홈 디렉터리 제외)
#
# 조치 전략:
#   - 목록 리포트 후 manual (의심 파일 포렌식 보존 필요)
#   - 자동 삭제 불가 (정상 파일 오삭제 위험)
#
# Rocky 8/9/10 공통

h_U_33_meta() {
    cat <<'JSON'
{
  "code": "U-33",
  "title": "숨겨진 파일 및 디렉토리 검색 및 제거",
  "severity": "하",
  "category": "파일 및 디렉토리 관리",
  "purpose": "숨겨진 파일 및 디렉토리 중 의심스러운 내용은 정상 사용자가 아닌 공격자에 의해 생성되었을 가능성이 높으므로 이를 제거하여 보안 위협을 방지하기 위함",
  "threat": "숨겨진 파일 및 디렉토리를 방치할 경우, 비인가자가 생성한 악성 파일 또는 백도어 등을 탐지하지 못할 위험이 존재함",
  "criterion_good": "불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거한 경우",
  "criterion_bad": "불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거하지 않은 경우",
  "action_method": "ls -al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 제거하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "숨겨진 파일 및 디렉토리 내 의심스러운 파일 존재 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-33 (2026 ver.)"
  ]
}
JSON
}

_u_33_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: find /tmp /var/tmp /dev/shm -name '.*' (의심스러운 임시 디렉터리 내 숨김 파일)"
        echo
        echo "## 임시 디렉터리 권한"
        ls -ld /tmp /var/tmp /dev/shm 2>&1 || true
        echo
        echo "## [1] 임시 디렉터리(/tmp,/var/tmp,/dev/shm) 내 의심 숨김 파일"
        local _l1; _l1=$(_u33_suspicious_in_tmp 2>/dev/null || true)
        if [[ -z "$_l1" ]]; then echo "(없음)"; else
            printf '%s\n' "$_l1" | while IFS= read -r f; do [[ -n "$f" ]] && printf "%s\n    조치: ls -la '%s' 확인 후 rm (포렌식 필요 시 먼저 백업)\n" "$f" "$f"; done
        fi
        echo
        echo "## [2] 이상한 이름(공백/점 연속) 숨김 파일"
        local _l2; _l2=$(_u33_suspicious_names 2>/dev/null || true)
        if [[ -z "$_l2" ]]; then echo "(없음)"; else
            printf '%s\n' "$_l2" | while IFS= read -r f; do [[ -n "$f" ]] && printf "%s\n    조치: file '%s' 확인 후 rm\n" "$f" "$f"; done
        fi
        echo
        echo "## [3] 실행 권한 있는 숨김 파일 (비홈·비컨테이너 경로)"
        local _l3; _l3=$(_u33_executable_hidden 2>/dev/null || true)
        if [[ -z "$_l3" ]]; then echo "(없음)"; else
            printf '%s\n' "$_l3" | while IFS= read -r f; do [[ -n "$f" ]] && printf "%s\n    조치: strings '%s' | head -20 확인 후 제거 또는 chmod -x\n" "$f" "$f"; done
        fi
    } | _evidence_capture "$label"
}


# 정상 숨김 파일 화이트리스트 패턴 (basename 기준)
_u33_normal_names() {
    cat <<'EOF'
.bash_history
.bash_profile
.bashrc
.bash_logout
.profile
.cshrc
.kshrc
.login
.logout
.viminfo
.lesshst
.ssh
.gnupg
.config
.local
.cache
.mozilla
.pki
.ansible
.gitconfig
.git
EOF
}

# 의심스러운 임시 디렉터리 내 숨김 파일 탐지
# 시스템 표준 소켓·작업 디렉터리(.X11-unix, .ICE-unix, .font-unix, .XIM-unix,
# .Test-unix, .esd-*, systemd private 등)는 정상이므로 제외.
# 추가로 _u33_normal_names (.viminfo, .bash_history 등) 도 basename 기준 제외 —
# 관리자가 root 로 tmp 에서 vim 사용 시 /tmp/.viminfo 생성되는 정상 케이스 대응.
_u33_suspicious_in_tmp() {
    local normal_basenames
    normal_basenames=$(_u33_normal_names | awk 'NF' | paste -sd'|' -)

    find /tmp /var/tmp /dev/shm \
        -maxdepth 3 -name '.*' \
        ! -path "${KISA_TMP_DIR:-/tmp/kisa-audit.XXXX}/*" \
        ! -name '.' ! -name '..' \
        ! -name '.X11-unix'       ! -path '*/.X11-unix/*' \
        ! -name '.XIM-unix'       ! -path '*/.XIM-unix/*' \
        ! -name '.ICE-unix'       ! -path '*/.ICE-unix/*' \
        ! -name '.font-unix'      ! -path '*/.font-unix/*' \
        ! -name '.Test-unix'      ! -path '*/.Test-unix/*' \
        ! -name '.esd-*'          ! -path '*/.esd-*/*' \
        ! -name '.wayland-*'      ! -path '*/.wayland-*/*' \
        ! -name '.Xauthority'     \
        2>/dev/null \
        | awk -v pats="$normal_basenames" '
            BEGIN { n=split(pats, arr, "|") }
            {
                bn=$0; sub(/.*\//, "", bn)
                skip=0
                for (i=1; i<=n; i++) if (bn == arr[i]) { skip=1; break }
                if (!skip) print
            }
        ' \
        | head -20
}

# 이름 이상(공백·점 연속) 숨김 파일 탐지 (시스템 전체)
# 컨테이너 이미지 레이어·factory 등 비-호스트 경로(_kisa_excluded_roots)는 제외.
_u33_suspicious_names() {
    local -a _p=(); _kisa_build_prune_expr _p
    _p+=( -o -path /proc -o -path /sys -o -path /dev/shm )
    find / \( "${_p[@]}" \) -prune -o \
        \( -name '.. ' -o -name '... ' -o -name '.  ' -o -name '.. .' \) \
        -print 2>/dev/null | head -20
}

# 실행 권한 있는 비홈 경로 숨김 파일 (컨테이너/factory 등 비-호스트 경로 제외)
_u33_executable_hidden() {
    local -a _p=(); _kisa_build_prune_expr _p
    _p+=( -o -path /proc -o -path /sys -o -path /home -o -path /root -o -path /dev )
    find / \( "${_p[@]}" \) -prune -o \
        -type f -name '.*' -perm /111 \
        -print 2>/dev/null | head -20
}

h_U_33_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_33_capture_state "$KISA_PHASE"
    fi

    local tmp_found exec_found name_found

    tmp_found=$(_u33_suspicious_in_tmp)
    name_found=$(_u33_suspicious_names)
    exec_found=$(_u33_executable_hidden)

    local issues=0
    [[ -n "$tmp_found"  ]] && (( issues++ ))
    [[ -n "$name_found" ]] && (( issues++ ))
    [[ -n "$exec_found" ]] && (( issues++ ))

    if (( issues == 0 )); then
        printf '양호 — 의심스러운 숨김 파일·디렉터리 없음'
        return 0
    fi

    local first=""
    [[ -n "$tmp_found"  ]] && first=$(printf '%s\n' "$tmp_found"  | head -1)
    [[ -z "$first" && -n "$exec_found" ]] && first=$(printf '%s\n' "$exec_found" | head -1)
    [[ -z "$first" && -n "$name_found" ]] && first=$(printf '%s\n' "$name_found" | head -1)

    printf '취약 — 의심 숨김 파일 발견 (임시디렉터리:%s 이상명:%s 실행가능:%s) 예: %s' \
        "$([ -n "$tmp_found"  ] && printf '있음' || printf '없음')" \
        "$([ -n "$name_found" ] && printf '있음' || printf '없음')" \
        "$([ -n "$exec_found" ] && printf '있음' || printf '없음')" \
        "$first"
    return 1
}

h_U_33_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) 의심 숨김 파일 목록 출력 후 수동 조치 안내 예정 (manual)'
        return 0
    fi

    local tmp_found exec_found name_found
    tmp_found=$(_u33_suspicious_in_tmp)
    name_found=$(_u33_suspicious_names)
    exec_found=$(_u33_executable_hidden)

    local total=0
    [[ -n "$tmp_found"  ]] && total=$(( total + $(printf '%s\n' "$tmp_found"  | wc -l | tr -d ' ') ))
    [[ -n "$name_found" ]] && total=$(( total + $(printf '%s\n' "$name_found" | wc -l | tr -d ' ') ))
    [[ -n "$exec_found" ]] && total=$(( total + $(printf '%s\n' "$exec_found" | wc -l | tr -d ' ') ))

    if (( total == 0 )); then
        printf '양호 — 이미 의심 숨김 파일 없음, 조치 불필요'
        return 0
    fi

    # 상세 목록·조치 명령은 evidence 영역(_u_33_capture_state)에 기록됨 — 콘솔엔 요약만.
    log_warn "U-33: 의심 숨김 파일 ${total}개 — 목록·조치는 report.html evidence 참조 (관리자 직접 확인·제거 필요)"

    printf '수동 조치 필요 — 의심 숨김 파일 %d개\n조치: 각 파일 내용 확인 후 제거 또는 chmod -x. 전체 목록은 아래 evidence 참조.' "$total"
    return 2
}
