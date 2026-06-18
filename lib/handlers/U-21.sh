#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-21: /etc/(r)syslog.conf 파일 소유자 및 권한 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: /etc/rsyslog.conf (Rocky Linux 기본), /etc/syslog.conf(구형),
#           /etc/rsyslog.d/*.conf 파일 소유자·권한 적절성
# 판단 기준:
#   양호: 소유자 root(또는 bin, sys), 권한 640 이하 (other 에 어떤 권한도 없음)
#   취약: 소유자 root/bin/sys 아님, 또는 권한 640 초과
#
# 조치 전략 (자동):
#   1) backup_file 각 대상 파일
#   2) chown root:root
#   3) chmod 640
#   4) rsyslogd -N1 로 설정 검증
#   5) restorecon
#   ※ rsyslog 재시작은 _queue_service_op 로 지연 처리
#
# 롤백 전략:
#   - backup_file 기록으로 restore_file 자동 원복
#   - rsyslog reload 도 큐잉
#
# Rocky 8/9/10 특이사항:
#   - rsyslog 패키지 사용. Rocky 9+ 에서 systemd-journald 병행 가능.
#   - /etc/syslog.conf 는 존재하지 않을 수 있음 (부재 시 건너뜀)

h_U_21_meta() {
    cat <<'JSON'
{
  "code": "U-21",
  "title": "/etc/(r)syslog.conf 파일 소유자 및 권한 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "/etc/(r)syslog.conf 파일의 권한 적절성을 점검하여, 비인가자의 임의적인 /etc/(r)syslog.conf 파일 변조를 방지하기 위함",
  "threat": "/etc/(r)syslog.conf 파일의 설정 내용을 참조하여 로그의 저장 위치가 노출되며 로그를 기록하지 않도록 설정하거나 대량의 로그를 기록하게 하여 시스템 과부하를 유도할 수 있는 위험이 존재함",
  "criterion_good": "/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우",
  "criterion_bad": "/etc/(r)syslog.conf 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640 이하가 아닌 경우",
  "action_method": "/etc/(r)syslog.conf 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "/etc/(r)syslog.conf 파일 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-21 (2026 ver.)"
  ]
}
JSON
}

_u_21_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/rsyslog.conf 소유자(root) + 권한(640 이하) 검증"
        echo
        echo "## rsyslog 패키지 + 서비스 상태"
        rpm -q rsyslog 2>&1 || true
        echo "is-enabled rsyslog: $(systemctl is-enabled rsyslog 2>&1)"
        echo "is-active  rsyslog: $(systemctl is-active  rsyslog 2>&1)"
        echo
        echo "## /etc/rsyslog.conf 권한"
        if [[ -f /etc/rsyslog.conf ]]; then
            ls -l /etc/rsyslog.conf 2>&1 || true
            stat -c 'mode=%a owner=%U group=%G' /etc/rsyslog.conf 2>&1 || true
        else
            echo "(/etc/rsyslog.conf 없음)"
        fi
        echo
        echo "## /etc/rsyslog.d 디렉터리 및 .conf 파일"
        if [[ -d /etc/rsyslog.d ]]; then
            ls -l /etc/rsyslog.d/ 2>&1 | head -20 || true
        else
            echo "(/etc/rsyslog.d 없음)"
        fi
        echo
        echo "## (legacy) /etc/syslog.conf"
        if [[ -f /etc/syslog.conf ]]; then
            ls -l /etc/syslog.conf 2>&1 || true
        else
            echo "(/etc/syslog.conf 없음 - rsyslog 기반 시스템)"
        fi
    } | _evidence_capture "$label"
}


_u21_main_conf()   { printf '/etc/rsyslog.conf'; }
_u21_legacy_conf() { printf '/etc/syslog.conf'; }
_u21_drop_dir()    { printf '/etc/rsyslog.d'; }

# 소유자 허용 목록: root, bin, sys
_u21_owner_ok() {
    local owner="$1"
    case "$owner" in
        root|bin|sys) return 0 ;;
        *) return 1 ;;
    esac
}

# 640 이하: other 에 r·w·x 없음  +  group 에 w·x 없음
_u21_perm_ok() {
    local mode="$1"
    (( (8#${mode:-0} & 8#037) == 0 ))
}

# 점검 대상 파일 목록
_u21_existing_targets() {
    local main;   main="$(_u21_main_conf)"
    local legacy; legacy="$(_u21_legacy_conf)"
    local ddir;   ddir="$(_u21_drop_dir)"

    [[ -f "$main" ]]   && printf '%s\n' "$main"
    [[ -f "$legacy" ]] && printf '%s\n' "$legacy"
    if [[ -d "$ddir" ]]; then
        find "$ddir" -maxdepth 1 -name '*.conf' -type f 2>/dev/null
    fi
}

h_U_21_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_21_capture_state "$KISA_PHASE"
    fi

    local targets
    targets=$(_u21_existing_targets)

    if [[ -z "$targets" ]]; then
        printf '해당없음 — rsyslog.conf 등 점검 대상 파일 없음'
        return 3
    fi

    local issues=()
    local f owner mode
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        owner=$(stat -c '%U' "$f" 2>/dev/null)
        mode=$(stat -c '%a' "$f" 2>/dev/null)
        _u21_owner_ok "$owner" || issues+=("${f}:소유자=${owner}")
        _u21_perm_ok "$mode"   || issues+=("${f}:권한=${mode}(640 초과)")
    done <<< "$targets"

    if [[ ${#issues[@]} -eq 0 ]]; then
        local fcount; fcount=$(printf '%s' "$targets" | wc -l)
        printf '양호 — rsyslog 설정 파일 %s건 모두 소유자 root(또는 bin/sys), 권한 640 이하' "${fcount//[[:space:]]/}"
        return 0
    fi

    printf '취약 — 소유자/권한 부적절: %s' "$(IFS='; '; printf '%s' "${issues[*]}")"
    return 1
}

h_U_21_apply() {
    local targets
    targets=$(_u21_existing_targets)

    if [[ "${1:-}" == "--dry-run" ]]; then
        if [[ -z "$targets" ]]; then
            printf '(dry-run) 점검 대상 rsyslog.conf 파일 없음 — 조치 예정 없음'
            return 0
        fi
        printf '(dry-run) rsyslog 설정 파일에 소유자 root:root, 권한 640 적용 예정'
        return 0
    fi

    if [[ -z "$targets" ]]; then
        printf '해당없음 — rsyslog.conf 등 점검 대상 파일 없음, 조치 불필요'
        return 3
    fi

    local changed=()
    local f owner mode
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        owner=$(stat -c '%U' "$f" 2>/dev/null)
        mode=$(stat -c '%a' "$f" 2>/dev/null)

        if _u21_owner_ok "$owner" && _u21_perm_ok "$mode"; then
            continue
        fi

        backup_file "$f"
        _u21_owner_ok "$owner" || chown root:root "$f"
        _u21_perm_ok "$mode"   || chmod 640 "$f"
        command -v restorecon >/dev/null 2>&1 && restorecon "$f" 2>/dev/null || true
        changed+=("$f")
    done <<< "$targets"

    if [[ ${#changed[@]} -eq 0 ]]; then
        printf '양호 — 이미 rsyslog 설정 파일 모두 소유자/권한 적절, 변경 불필요'
        return 0
    fi

    # rsyslog 설정 검증
    if command -v rsyslogd >/dev/null 2>&1; then
        if ! rsyslogd -N1 2>/dev/null; then
            local m
            for m in "${changed[@]}"; do restore_file "$m" || true; done
            printf '조치 실패 — rsyslogd -N1 설정 검증 실패, 변경 원복 완료'
            return 1
        fi
    fi

    _queue_service_op reload rsyslog
    _queue_rollback   systemctl_reload rsyslog

    printf '조치 완료 — rsyslog 설정 파일 %s건 소유자/권한 변경(root:root, 640); rsyslog reload 지연' "${#changed[@]}"
    return 0
}
