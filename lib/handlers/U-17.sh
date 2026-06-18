#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-17: 시스템 시작 스크립트 권한 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: 시스템 시작 스크립트 파일 소유자(root) 및 other 쓰기 권한 설정 적절성
# 판단 기준:
#   양호: 소유자 root, other(o) 쓰기 권한 없음
#   취약: 소유자 root 아님, 또는 other 쓰기 권한 존재
#
# 조치 전략:
#   점검 경로:
#     - /etc/systemd/system/    (Rocky Linux 기본 — systemd unit)
#     - /usr/lib/systemd/system/ (패키지 설치 unit, 읽기 전용 참조용)
#     - /etc/rc.d/              (legacy, 존재 시)
#   자동 조치:
#     - other 쓰기 권한(o+w) 제거: chmod o-w
#     - 소유자 변경(root 아닌 경우): chown root
#   한계:
#     - /usr/lib/systemd/system/ 는 패키지 관리 파일 → 자동 chmod 적용하되 패키지 업데이트 시 원복 가능 경고
#     - 취약 파일 20건 이상이면 전체 목록 파일에 저장하고 일부만 샘플 출력
#
# 롤백 전략:
#   - backup_file 은 per-file; 대량일 경우 파일별 backup_file 후 chmod/chown
#
# Rocky 8/9/10 특이사항:
#   - systemd 전용. /etc/rc.d/rc.local 존재 시 동일 점검.

h_U_17_meta() {
    cat <<'JSON'
{
  "code": "U-17",
  "title": "시스템 시작 스크립트 권한 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "시스템 시작 스크립트 파일을 관리자만 제어할 수 있게 하여 비인가자들의 임의적인 파일 변조를 방지하기 위함",
  "threat": "시스템 시작 스크립트 파일의 소유권 및 권한 설정이 미흡할 경우, 비인가자가 스크립트의 내용 변경 등을 통해 시스템 침입 등 악용할 위험이 존재함",
  "criterion_good": "시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자의 쓰기 권한이 제거된 경우",
  "criterion_bad": "시스템 시작 스크립트 파일의 소유자가 root가 아니거나, 일반 사용자의 쓰기 권한이 부여된 경우",
  "action_method": "시스템 시작 스크립트 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "시스템 시작 스크립트 파일 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-17 (2026 ver.)"
  ]
}
JSON
}

_u_17_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 시스템 시작 스크립트 권한 (other 쓰기 없음, 소유자 root)"
        echo
        echo "## /etc/rc.d, /etc/systemd/system, /usr/lib/systemd/system 디렉터리 상태"
        for _d in /etc/rc.d /etc/systemd/system /usr/lib/systemd/system; do
            [[ -d "$_d" ]] || continue
            ls -ld "$_d" 2>&1 || true
        done
        echo
        echo "## /etc/rc.d/rc.local"
        ls -l /etc/rc.d/rc.local 2>&1 || true
        echo
        echo "## other 쓰기 권한이 있는 시작 스크립트 파일 검색"
        for _d in /etc/systemd/system /usr/lib/systemd/system /etc/rc.d; do
            [[ -d "$_d" ]] || continue
            find "$_d" -maxdepth 3 -type f -perm /002 2>/dev/null | head -20
        done
        echo
        echo "## 비-root 소유 시작 스크립트 검색"
        for _d in /etc/systemd/system /usr/lib/systemd/system /etc/rc.d; do
            [[ -d "$_d" ]] || continue
            find "$_d" -maxdepth 3 -type f \! -uid 0 2>/dev/null | head -20
        done
    } | _evidence_capture "$label"
}


_u17_scan_dirs() {
    printf '%s\n' \
        '/etc/systemd/system' \
        '/usr/lib/systemd/system' \
        '/etc/rc.d'
}

_u17_report_path() {
    [[ -n "${KISA_TMP_DIR:-}" ]] || { echo "KISA_TMP_DIR 미설정" >&2; return 1; }
    printf '%s/u17_vuln_scripts.txt' "$KISA_TMP_DIR"
}

# other 쓰기 bit 체크: mode & 0002 != 0
_u17_has_owrite() {
    local mode="$1"
    local m; m=$(printf '%d' "0${mode}" 2>/dev/null || printf '0')
    (( (m & 02) != 0 ))
}

# 취약 파일 목록 생성 (report_path 에 저장)
_u17_find_vuln() {
    local report; report="$(_u17_report_path)"
    mkdir -p "$(dirname "$report")" 2>/dev/null || true
    : > "$report"

    local d
    while IFS= read -r d; do
        [[ -d "$d" ]] || continue
        find "$d" -type f 2>/dev/null | while IFS= read -r f; do
            local owner mode
            owner=$(stat -c '%U' "$f" 2>/dev/null || printf 'unknown')
            mode=$(stat -c '%a' "$f" 2>/dev/null || printf '000')
            local bad=0
            [[ "$owner" != "root" ]] && bad=1
            _u17_has_owrite "$mode" && bad=1
            if (( bad )); then
                printf '%s owner=%s mode=%s\n' "$f" "$owner" "$mode" >> "$report"
            fi
        done
    done < <(_u17_scan_dirs)
}

h_U_17_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_17_capture_state "$KISA_PHASE"
    fi

    local report; report="$(_u17_report_path)"
    _u17_find_vuln

    local count
    count=$(wc -l < "$report" 2>/dev/null || printf '0')
    count="${count//[[:space:]]/}"

    if [[ "$count" -eq 0 ]]; then
        printf '양호 — 시작 스크립트 소유자·권한 이상 없음'
        return 0
    fi

    local sample
    sample=$(head -3 "$report" | awk '{print $1}' | tr '\n' ' ')
    printf '취약 — 시작 스크립트 %s건 (샘플: %s); 전체 목록: %s' \
        "$count" "$sample" "$report"
    return 1
}

h_U_17_apply() {
    local report; report="$(_u17_report_path)"

    if [[ "${1:-}" == "--dry-run" ]]; then
        # 보고서 없으면 재스캔
        [[ -f "$report" ]] || _u17_find_vuln
        local count; count=$(wc -l < "$report" 2>/dev/null || printf '0')
        count="${count//[[:space:]]/}"
        if [[ "$count" -eq 0 ]]; then
            printf '(dry-run) 취약 파일 없음 — 변경 불필요'
        else
            printf '(dry-run) 취약 파일 %s건에 chown root + chmod o-w 적용 예정; 전체: %s' \
                "$count" "$report"
        fi
        return 0
    fi

    [[ -f "$report" ]] || _u17_find_vuln

    local count; count=$(wc -l < "$report" 2>/dev/null || printf '0')
    count="${count//[[:space:]]/}"

    if [[ "$count" -eq 0 ]]; then
        printf '양호 — 이미 취약 파일 없음, 조치 불필요'
        return 0
    fi

    local fixed=0 failed=0
    local f owner mode
    while IFS=' ' read -r f owner_kv mode_kv; do
        [[ -f "$f" ]] || continue
        owner="${owner_kv#owner=}"
        mode="${mode_kv#mode=}"

        backup_file "$f"

        local ok=1
        if [[ "$owner" != "root" ]]; then
            chown root "$f" 2>/dev/null || ok=0
        fi
        if _u17_has_owrite "$mode"; then
            chmod o-w "$f" 2>/dev/null || ok=0
        fi
        command -v restorecon >/dev/null 2>&1 && restorecon "$f" 2>/dev/null || true

        if (( ok )); then
            (( fixed++ ))
        else
            (( failed++ ))
        fi
    done < "$report"

    if [[ "$failed" -eq 0 ]]; then
        printf '조치 완료 — 시작 스크립트 %s건 권한 변경 (chown root + chmod o-w)' "$fixed"
        return 0
    else
        printf '조치 실패 — %s건 처리, %s건 실패; 실패 파일 수동 확인 필요' "$fixed" "$failed"
        return 1
    fi
}
