#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-64: 주기적 보안 패치 및 벤더 권고사항 적용 (중요도: 상)
# KISA 가이드: 최신 보안 패치가 주기적으로 적용되고 있는지 점검한다.
#
# 판단 기준:
#   양호 — 가용 보안 업데이트 없음 OR 마지막 패치 30일 이내
#   취약 — 가용 보안 업데이트 존재 AND 마지막 패치 30일 이상 경과
#
# 조치 전략:
#   apply 는 항상 수동 조치 안내 (return 2). OS 패치는 운영자가
#   "dnf update --security -y" 또는 "dnf update -y" 직접 수행.
#   자동 패치는 시스템 영향이 크므로 audit.conf 변수로 제어하지 않음.
#
# 롤백 전략:
#   패키지 업데이트는 시스템 재부팅·서비스 재시작이 필요할 수 있어 자동 롤백 불가.

h_U_64_meta() {
    cat <<'JSON'
{
  "code": "U-64",
  "title": "주기적 보안 패치 및 벤더 권고사항 적용",
  "severity": "상",
  "category": "패치 관리",
  "purpose": "주기적인 패치 적용을 통해 시스템 안정성 및 보안성을 확보하기 위함",
  "threat": "최신 보안패치가 적용되지 않을 경우, 이미 알려진 취약점을 통하여 공격자에 의해 시스템 침해사고 발생할 위험이 존재함",
  "criterion_good": "패치 적용 정책을 수립하여 주기적으로 패치 관리를 하고 있으며, 패치 관련 내용을 확인하고 적용하였을 경우",
  "criterion_bad": "패치 적용 정책을 수립하지 않고 주기적으로 패치 관리를 하지 않거나, 패치 관련 내용을 확인하지 않고 적용하지 않고 있는 경우",
  "action_method": "OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 OS 관리자 및 벤더에서 적용하도록 설정 ※ OS 패치의 경우 지속해서 취약점이 발표되고 있으므로 O/S 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책을 수립하여 적용해야 함",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "시스템에서 최신 패치가 적용 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-64 (2026 ver.)"
  ]
}
JSON
}

_u_64_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 보안 패치 적용 상태"
        echo
        echo "## OS 정보"
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release 2>/dev/null
            echo "OS: ${PRETTY_NAME:-unknown}"
        fi
        echo "Kernel: $(uname -r 2>&1)"
        echo
        echo "## 가용 보안 업데이트 (dnf updateinfo list security)"
        if command -v dnf >/dev/null 2>&1; then
            dnf -q updateinfo list security --available 2>/dev/null | head -30 || true
            echo
            echo "### 보안 업데이트 카운트"
            local _cnt
            _cnt=$(dnf -q updateinfo list security --available 2>/dev/null | grep -cE '^RHSA|^FEDORA|^[A-Z]+-[0-9]+' || printf '0')
            echo "보안 업데이트 가용: ${_cnt}건"
        else
            echo "(dnf 명령 없음)"
        fi
        echo
        echo "## 마지막 패치 시각 (rpm -qa --last 의 최신 항목)"
        rpm -qa --last 2>/dev/null | head -5 || true
        echo
        echo "## 패치 정책: 운영자 수동 조치 (audit.conf 자동 패치 변수 없음)"
    } | _evidence_capture "$label"
}


_u64_pkg_mgr()      { printf '%s' "${PKG_MGR:-dnf}"; }
_u64_rpm_log()      { printf '/var/log/dnf.rpm.log'; }
_u64_rpm_log_alt()  { printf '/var/log/yum.log'; }
_u64_history_log()  { printf '/var/log/dnf.log'; }

# 마지막 패치 적용 일자를 epoch 초로 반환 (없으면 0)
_u64_last_update_epoch() {
    local mgr; mgr="$(_u64_pkg_mgr)"
    local epoch=0 ts

    # dnf history 기준 (rocky 8/9/10 공통)
    if command -v dnf >/dev/null 2>&1; then
        ts=$(dnf history list 2>/dev/null \
            | awk 'NR>2 && /[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
                    match($0, /([0-9]{4}-[0-9]{2}-[0-9]{2})/, a)
                    if (a[1] != "") { print a[1]; exit }
                  }')
        if [[ -n "$ts" ]]; then
            epoch=$(date -d "$ts" +%s 2>/dev/null || printf '0')
        fi
    fi

    # fallback: rpm log
    if (( epoch == 0 )); then
        local logf
        logf="$(_u64_rpm_log)"
        [[ -r "$logf" ]] || logf="$(_u64_rpm_log_alt)"
        if [[ -r "$logf" ]]; then
            ts=$(awk '/[Ii]nstalled|[Uu]pdated/{ts=$1" "$2} END{print ts}' "$logf")
            [[ -n "$ts" ]] && epoch=$(date -d "$ts" +%s 2>/dev/null || printf '0')
        fi
    fi

    printf '%d' "$epoch"
}

# 가용 보안 업데이트 건수 (check-update --security exit=100 있으면 취약)
_u64_security_update_count() {
    local count
    count=$(dnf check-update --security -q 2>/dev/null | grep -cE '^[a-zA-Z0-9]' || true)
    printf '%d' "${count:-0}"
}

h_U_64_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_64_capture_state "$KISA_PHASE"
    fi

    if ! command -v dnf >/dev/null 2>&1; then
        printf 'dnf 명령 없음 — 판정 불가'
        return 2
    fi

    local now epoch age_days avail_count
    now=$(date +%s)
    epoch=$(_u64_last_update_epoch)
    avail_count=$(_u64_security_update_count)

    if (( epoch == 0 )); then
        age_days=9999
    else
        age_days=$(( (now - epoch) / 86400 ))
    fi

    if (( avail_count == 0 )); then
        printf '양호 — 가용 보안 업데이트 없음 (마지막 패치 %d일 전)' "$age_days"
        return 0
    fi

    if (( age_days < 30 )); then
        printf '양호 — 보안 업데이트 %d건 존재하나 마지막 패치 %d일 이내' "$avail_count" "$age_days"
        return 0
    fi

    printf '취약 — 보안 업데이트 %d건 미적용, 마지막 패치 %d일 경과' "$avail_count" "$age_days"
    return 1
}

h_U_64_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) OS 보안 패치는 수동 안내 — 운영자가 dnf update --security -y 또는 dnf update -y 직접 수행\n'
        printf '[dry-run] 가용 보안 패치 목록:\n'
        dnf check-update --security -q 2>/dev/null | head -40 || true
        return 2
    fi

    printf '수동 조치 필요 — OS 보안 패치\n조치: 운영자가 직접 "dnf update --security -y" 또는 "dnf update -y" 실행 후 reboot (커널 패치 포함)'
    return 2
}
