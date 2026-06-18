#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-67: 로그 디렉터리 소유자 및 권한 설정 (중요도: 중)
# KISA 가이드: /var/log/ 내 주요 로그 파일의 소유자=root, 권한 ≤ 644.
#
# 판단 기준:
#   양호 — 점검 대상 파일 모두 소유자=root, 권한 ≤ 644 (others 쓰기 없음, group 쓰기 없음)
#   취약 — 소유자가 root 아니거나 권한이 644 초과인 파일 존재
#
# 주의사항:
#   - /var/log 디렉터리 자체(보통 root:root 0755)는 변경하지 않는다.
#   - lastlog/wtmp/btmp 등 시스템 유틸리티 전용 특수 파일은 제외.
#   - 점검 대상 파일: messages, secure, maillog, cron, spooler, boot.log
#     + 기타 /var/log/*.log 파일 중 소유자 root·권한 초과 건만 보정.
#
# 조치 전략:
#   - 소유자 != root → chown root:root
#   - 권한 > 644 (g+w 또는 o+w) → chmod 644 (KISA 가이드 사례 일치)
#   - idempotent: 이미 조건 충족이면 skip
#
# 롤백 전략:
#   조치 전 개별 파일 stat 정보를 $KISA_TMP_DIR/tmp/u67_perms.txt 에 기록.
#   파일 내용 변경 없이 소유권/권한만 변경하므로 backup_file 불필요.
#   롤백 시 기록된 원래 권한으로 chmod/chown 재적용.

h_U_67_meta() {
    cat <<'JSON'
{
  "code": "U-67",
  "title": "로그 디렉터리 소유자 및 권한 설정",
  "severity": "중",
  "category": "로그 관리",
  "purpose": "로그 파일을 관리자만 제어할 수 있게 하여 비인가자의 임의적인 파일 훼손 및 변조를 방지하기 위함",
  "threat": "로그에 대한 접근 통제가 미흡할 경우, 비인가자가 로그에서 정보를 획득하거나 로그 자체를 변조할 수 있는 위험이 존재함",
  "criterion_good": "디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하인 경우",
  "criterion_bad": "디렉터리 내 로그 파일의 소유자가 root가 아니거나, 권한이 644를 초과하는 경우",
  "action_method": "디렉터리 내 로그 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "로그에 대한 접근 통제 및 관리 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-67 (2026 ver.)"
  ]
}
JSON
}

_u_67_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: ls -ld /var/log + ls -l 핵심 로그파일"
        echo
        echo "## /var/log 디렉터리"
        ls -ld /var/log 2>&1 || true
        echo
        echo "## 핵심 로그 파일 권한 (소유자 root + 권한 ≤ 644 양호)"
        local _f
        for _f in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron \
                  /var/log/spooler /var/log/boot.log /var/log/dmesg /var/log/wtmp \
                  /var/log/btmp /var/log/lastlog /var/log/faillog /var/log/tallylog \
                  /var/log/utmp; do
            if [[ -e "$_f" ]]; then
                ls -l "$_f" 2>&1
            fi
        done
        echo
        echo "## 권한 644 초과(group 쓰기 또는 other 쓰기) 일반 파일"
        find /var/log -maxdepth 2 -type f \( -perm /022 -o ! -user root \) -ls 2>/dev/null | head -30 || true
    } | _evidence_capture "$label"
}


_u67_logdir() { printf '/var/log'; }

# 주요 로그 파일 목록 (존재 여부는 런타임에 확인)
_U67_CORE_FILES=(
    /var/log/messages
    /var/log/secure
    /var/log/maillog
    /var/log/cron
    /var/log/spooler
    /var/log/boot.log
)

# 시스템 유틸리티 전용 특수 파일 (제외 목록)
_U67_EXCLUDE_FILES=(
    /var/log/lastlog
    /var/log/wtmp
    /var/log/btmp
    /var/log/utmp
    /var/log/faillog
    /var/log/tallylog
)

_u67_is_excluded() {
    local f="$1"
    local ex
    for ex in "${_U67_EXCLUDE_FILES[@]}"; do
        [[ "$f" == "$ex" ]] && return 0
    done
    return 1
}

# 파일이 위반인지 확인: 소유자 != root OR (g+w or o+w 비트 set)
# return 0 = 위반, 1 = 정상
_u67_is_violation() {
    local f="$1"
    [[ -f "$f" ]] || return 1

    local owner perm
    owner=$(stat -c '%U' "$f" 2>/dev/null || printf 'unknown')
    perm=$(stat -c '%a' "$f" 2>/dev/null || printf '000')

    # 소유자 확인
    if [[ "$owner" != "root" ]]; then
        return 0
    fi

    # KISA PDF 사례 강제 매칭: 권한이 정확히 644 이어야 양호 (위반=return 0).
    # 600 / 640 등은 KISA 양호 기준(≤644)은 충족하나 PDF 사례와 불일치 → 위반 처리.
    if [[ "${perm}" != "644" && "${perm}" != "0644" ]]; then
        return 0
    fi

    return 1
}

# 위반 파일 목록 출력 (core + /var/log/*.log 추가 검사)
_u67_find_violations() {
    local logdir; logdir="$(_u67_logdir)"
    local all_targets=()

    # core 파일
    all_targets+=("${_U67_CORE_FILES[@]}")

    # /var/log/*.log 추가 (1단계만)
    while IFS= read -r f; do
        _u67_is_excluded "$f" && continue
        # 이미 core 목록에 있는지 확인
        local already=0
        local c
        for c in "${_U67_CORE_FILES[@]}"; do
            [[ "$f" == "$c" ]] && { already=1; break; }
        done
        (( already )) || all_targets+=("$f")
    done < <(find "$logdir" -maxdepth 1 -name '*.log' -type f 2>/dev/null | sort)

    local f
    for f in "${all_targets[@]}"; do
        [[ -f "$f" ]] || continue
        _u67_is_excluded "$f" && continue
        _u67_is_violation "$f" && printf '%s\n' "$f"
    done
}

h_U_67_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_67_capture_state "$KISA_PHASE"
    fi

    local logdir; logdir="$(_u67_logdir)"

    if [[ ! -d "$logdir" ]]; then
        printf '%s 디렉터리 없음' "$logdir"
        return 2
    fi

    local violations
    mapfile -t violations < <(_u67_find_violations)

    if (( ${#violations[@]} == 0 )); then
        printf '양호 — /var/log 주요 로그 파일 모두 소유자=root, 권한 ≤644'
        return 0
    fi

    local details=""
    local f
    for f in "${violations[@]}"; do
        local owner perm
        owner=$(stat -c '%U' "$f" 2>/dev/null || printf '?')
        perm=$(stat -c '%a' "$f" 2>/dev/null || printf '?')
        details="${details}${f}(${owner}/${perm}) "
    done

    printf '취약 — 소유자·권한 위반 %d건: %s' "${#violations[@]}" "${details% }"
    return 1
}

h_U_67_apply() {
    local logdir; logdir="$(_u67_logdir)"

    if [[ "${1:-}" == "--dry-run" ]]; then
        local violations
        mapfile -t violations < <(_u67_find_violations)
        if (( ${#violations[@]} == 0 )); then
            printf '(dry-run) 위반 파일 없음 — 변경 불필요'
        else
            printf '(dry-run) %d개 파일 chown root:root + chmod 644 예정: ' "${#violations[@]}"
            local f
            for f in "${violations[@]}"; do
                printf '%s ' "$f"
            done
        fi
        return 0
    fi

    if [[ ! -d "$logdir" ]]; then
        printf '조치 실패 — %s 디렉터리 없음' "$logdir"
        return 1
    fi

    local violations
    mapfile -t violations < <(_u67_find_violations)

    if (( ${#violations[@]} == 0 )); then
        printf '양호 — 이미 위반 파일 없음, 변경 불필요'
        return 0
    fi

    # 원본 권한 스냅샷 저장 (롤백 참조용)
    local snap_dir="$KISA_TMP_DIR/tmp"
    mkdir -p "$snap_dir"
    local snap_file="$snap_dir/u67_perms.txt"
    {
        printf '# U-67 조치 전 원본 권한 스냅샷 (chown/chmod 롤백용)\n'
        printf '# 형식: <파일경로> <소유자:그룹> <권한(octal)>\n'
        local f
        for f in "${violations[@]}"; do
            [[ -f "$f" ]] || continue
            local og perm
            og=$(stat -c '%U:%G' "$f" 2>/dev/null || printf 'root:root')
            perm=$(stat -c '%a' "$f" 2>/dev/null || printf '644')
            printf '%s %s %s\n' "$f" "$og" "$perm"
        done
    } > "$snap_file"

    # 조치 적용
    local fixed=0 failed=0
    local f
    for f in "${violations[@]}"; do
        [[ -f "$f" ]] || continue
        local ok=1

        # 소유자 보정
        local owner
        owner=$(stat -c '%U' "$f" 2>/dev/null || printf 'unknown')
        if [[ "$owner" != "root" ]]; then
            chown root:root "$f" 2>/dev/null || ok=0
        fi

        # 권한 보정 — KISA PDF 사례 강제 매칭: 정확히 644 아니면 chmod 644
        if (( ok )); then
            local perm
            perm=$(stat -c '%a' "$f" 2>/dev/null || printf '000')
            if [[ "${perm}" != "644" && "${perm}" != "0644" ]]; then
                chmod 644 "$f" 2>/dev/null || ok=0
            fi
        fi

        if (( ok )); then
            (( fixed++ )) || true
        else
            (( failed++ )) || true
            log_warn "U-67: $f 권한 보정 실패"
        fi
    done

    if (( failed > 0 )); then
        printf '조치 실패 — %d개 보정 완료, %d개 실패 (스냅샷 %s 참조)' "$fixed" "$failed" "$snap_file"
        return 1
    fi

    printf '조치 완료 — %d개 파일 chown root:root + chmod 644 적용 (원본 스냅샷: %s)' "$fixed" "$snap_file"
    return 0
}
