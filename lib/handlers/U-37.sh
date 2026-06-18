#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-37: crontab 설정파일 권한 설정 미흡 (중요도: 상)
# KISA 가이드: cron/at 관련 파일·디렉터리 권한을 root 소유·제한 권한으로 설정.
#
# 판단 기준:
#   양호: /etc/crontab 권한 640 이하, /etc/cron.{hourly,daily,weekly,monthly,d}/ 권한 750 이하,
#         /var/spool/cron 권한 700 이하, /usr/bin/crontab 권한 750 이하, 소유자 root
#   취약: 위 조건 불충족
#
# 조치 전략:
#   - /etc/crontab → chmod 640, chown root:root
#   - /etc/cron.{hourly,daily,weekly,monthly,d} → chmod 750, chown root:root
#   - /var/spool/cron → chmod 700, chown root:root
#   - /usr/bin/crontab → chmod 750, chown root:root (SUID 제거 포함)
#   - at 관련 파일은 정보 제공 수준 (수동 조치 권고)
#
# 롤백 전략: backup_file 으로 stat 기록됨 (mode/owner).

h_U_37_meta() {
    cat <<'JSON'
{
  "code": "U-37",
  "title": "crontab 설정파일 권한 설정 미흡",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "관리자 외에는 cron/at 서비스를 사용할 수 없도록 설정하고 있는지 점검",
  "threat": "일반 사용자가 crontab 및 at 서비스를 사용할 경우, 고의 또는 실수로 불법적인 예약 파일 실행으로 시스템 피해를 일으킬 수 있는 위험이 존재함",
  "criterion_good": "crontab 및 at 명령어에 일반 사용자 실행 권한이 제거되어 있으며, cron 및 at 관련 파일 권한이 640 이하인 경우",
  "criterion_bad":  "crontab 및 at 명령어에 일반 사용자 실행 권한이 부여되어 있으며, cron 및 at 관련 파일 권한이 640 이상인 경우",
  "method": [
    "ls -l /usr/bin/crontab",
    "ls -l /etc/crontab",
    "ls -ld /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d",
    "ls -ld /var/spool/cron"
  ],
  "action_method": "crontab 및 at 명령어 파일 권한 750 이하, cron 및 at 관련 파일 소유자 root, 권한 640 이하 설정 (디렉터리는 750)",
  "action_impact": "일반적인 경우 영향 없음",
  "references": ["KISA 가이드 U-37 (2026 ver.)"]
}
JSON
}

# 현재 cron 관련 파일/디렉터리의 소유자·권한을 ls 형태로 캡처해 evidence 로 기록.
# label 인자 (before|after) 로 단계 구분.
_u37_capture_state() {
    local label="$1"
    {
        echo "# ls -l /usr/bin/crontab"
        ls -l /usr/bin/crontab 2>&1 || true
        echo
        echo "# ls -l /etc/crontab"
        ls -l /etc/crontab 2>&1 || true
        echo
        echo "# ls -ld /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d"
        ls -ld /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d 2>&1 || true
        echo
        echo "# ls -ld /var/spool/cron"
        ls -ld /var/spool/cron 2>&1 || true
    } | _evidence_capture "$label"
}

# 파일/디렉터리 소유자가 root 이고 권한이 max_mode 이하인지 확인
# return 0 = 양호, 1 = 취약, 2 = 대상 없음
_u37_check_perm() {
    local path="$1" max_mode="$2"
    [[ -e "$path" ]] || return 2
    local owner perm
    owner=$(stat -c '%U' "$path" 2>/dev/null)
    perm=$(stat -c '%a' "$path" 2>/dev/null)
    if [[ "$owner" != "root" ]]; then return 1; fi
    # perm 이 max_mode 이하인지 — 8진수 비교
    if (( 8#$perm <= 8#$max_mode )); then return 0; else return 1; fi
}

h_U_37_check() {
    # 매 호출마다 evidence 캡처 — apply 모드에서는 _check 가 두 번 호출되므로
    # before/after 가 자동 분리됨 (run_handler 가 KISA_PHASE 를 채워줌).
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u37_capture_state "$KISA_PHASE"
    fi

    local issues=()

    # /etc/crontab, /etc/anacrontab — 640 이하
    local r; local f
    for f in /etc/crontab /etc/anacrontab; do
        [[ -f "$f" ]] || continue
        _u37_check_perm "$f" 640; r=$?
        if (( r == 1 )); then
            local p; p=$(stat -c '%a' "$f" 2>/dev/null)
            issues+=("$f 권한 $p (640 이하 필요)")
        fi
    done

    # /etc/cron.* 디렉터리 — 750 이하
    local d
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        _u37_check_perm "$d" 750; r=$?
        if (( r == 1 )); then
            local p; p=$(stat -c '%a' "$d" 2>/dev/null)
            issues+=("$d 권한 $p (750 이하 필요)")
        fi
    done

    # /etc/cron.d 안의 파일 — 데이터 파일 640 이하
    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            case "$f" in *.kisa.bak|*.kisa.bak.absent) continue ;; esac
            _u37_check_perm "$f" 640; r=$?
            if (( r == 1 )); then
                local p; p=$(stat -c '%a' "$f" 2>/dev/null)
                issues+=("$f 권한 $p (640 이하 필요)")
            fi
        done
    fi

    # cron.allow / cron.deny / at.allow / at.deny — 데이터 파일 640 이하
    for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
        [[ -e "$f" ]] || continue
        _u37_check_perm "$f" 640; r=$?
        if (( r == 1 )); then
            local p; p=$(stat -c '%a' "$f" 2>/dev/null)
            issues+=("$f 권한 $p (640 이하 필요)")
        fi
    done

    # /var/spool/cron — 700 이하
    _u37_check_perm /var/spool/cron 700; r=$?
    if (( r == 1 )); then
        local p; p=$(stat -c '%a' /var/spool/cron 2>/dev/null)
        issues+=("/var/spool/cron 권한 $p (700 이하 필요)")
    fi

    # /usr/bin/crontab, /usr/bin/at — 750 이하 + SUID 제거 (KISA U-37 PDF)
    for f in /usr/bin/crontab /usr/bin/at; do
        [[ -f "$f" ]] || continue
        local p; p=$(stat -c '%a' "$f" 2>/dev/null)
        local base=$((8#${p} & 0777)) suid=$((8#${p} & 04000))
        if (( suid != 0 )); then
            issues+=("$f SUID 비트 설정됨 ($p, 제거 필요)")
        elif (( base > 8#750 )); then
            issues+=("$f 권한 $p (750 이하 필요)")
        fi
    done

    if (( ${#issues[@]} == 0 )); then
        printf '양호 — cron 관련 파일/디렉터리 권한 적정 (소유자 root, 권한 기준 이하)'
        return 0
    fi

    printf '취약 — %s' "${issues[*]}"
    return 1
}

h_U_37_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_37_check >/dev/null 2>&1; rc=$?
        if (( rc == 0 )); then
            printf '(dry-run) 이미 양호 — 조치 불필요'
        else
            printf '(dry-run) cron 관련 파일/디렉터리 chmod/chown 예정'
        fi
        return 0
    fi

    local rc; h_U_37_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 cron 관련 파일/디렉터리 권한 적정'; return 0; fi

    local changed=0
    local f d

    # /etc/crontab, /etc/anacrontab — 640
    for f in /etc/crontab /etc/anacrontab; do
        [[ -f "$f" ]] || continue
        _u37_check_perm "$f" 640; rc=$?
        if (( rc == 1 )); then
            backup_file "$f"
            chown root:root "$f"
            chmod 640 "$f"
            changed=1
        fi
    done

    # /etc/cron.* 디렉터리 — 750
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        [[ -d "$d" ]] || continue
        _u37_check_perm "$d" 750; rc=$?
        if (( rc == 1 )); then
            chown root:root "$d"
            chmod 750 "$d"
            changed=1
        fi
    done

    # /etc/cron.d 안의 파일 — 640
    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            case "$f" in *.kisa.bak|*.kisa.bak.absent) continue ;; esac
            _u37_check_perm "$f" 640; rc=$?
            if (( rc == 1 )); then
                backup_file "$f"
                chown root:root "$f"
                chmod 640 "$f"
                changed=1
            fi
        done
    fi

    # cron.allow/deny, at.allow/deny — 640
    for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
        [[ -e "$f" ]] || continue
        _u37_check_perm "$f" 640; rc=$?
        if (( rc == 1 )); then
            backup_file "$f"
            chown root:root "$f"
            chmod 640 "$f"
            changed=1
        fi
    done

    # /var/spool/cron
    if [[ -d /var/spool/cron ]]; then
        _u37_check_perm /var/spool/cron 700; rc=$?
        if (( rc == 1 )); then
            chown root:root /var/spool/cron
            chmod 700 /var/spool/cron
            changed=1
        fi
    fi

    # /usr/bin/crontab, /usr/bin/at — SUID 제거 + 750
    for f in /usr/bin/crontab /usr/bin/at; do
        [[ -f "$f" ]] || continue
        local p; p=$(stat -c '%a' "$f" 2>/dev/null)
        local suid=$((8#${p} & 04000)) base=$((8#${p} & 0777))
        if (( suid != 0 )) || (( base > 8#750 )); then
            backup_file "$f"
            chown root:root "$f"
            chmod 0750 "$f"
            chmod u-s "$f" 2>/dev/null || true
            changed=1
        fi
    done

    if (( changed == 0 )); then
        printf '양호 — 이미 cron 관련 파일/디렉터리 권한 적정'
        return 0
    fi

    printf '조치 완료 — cron 관련 파일/디렉터리 chmod/chown 적용'
    return 0
}
