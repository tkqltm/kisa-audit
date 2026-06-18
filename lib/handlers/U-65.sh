#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-65: NTP 및 시각 동기화 설정 (중요도: 중)
# KISA 가이드: chronyd 가 활성화되어 있고, 승인된 NTP 서버와 동기화 중임을 확인.
#
# Rocky 8/9/10 모두 chrony 사용 (ntpd 미사용).
#   패키지: chrony  /  서비스 유닛: chronyd  /  설정: /etc/chrony.conf
#
# 판단 기준:
#   양호 — chronyd 활성(active+enabled) + timedatectl NTP=active
#   취약 — chronyd 비활성 OR NTP 비동기
#
# 환경변수:
#   NTP_SERVERS — 콤마 구분 NTP 서버 목록 (기본: kr.pool.ntp.org,time.bora.net)
#
# 조치 전략:
#   1) chrony 패키지 없으면 return 2 (설치는 사용자 판단)
#   2) chrony.conf 의 기존 ^(pool|server) 라인을 awk 로 주석 처리
#   3) NTP_SERVERS 콤마 목록을 "server <addr> iburst" 라인으로 추가
#   4) chronyd 활성화 + restart 큐잉
#
# 롤백 전략:
#   backup_file /etc/chrony.conf → restore_file
#   _queue_rollback systemctl_restart chronyd

h_U_65_meta() {
    cat <<'JSON'
{
  "code": "U-65",
  "title": "NTP 및 시각 동기화 설정",
  "severity": "중",
  "category": "로그 관리",
  "purpose": "인증 및 감사 목적을 위한 시간 동기화는 필수적이며, 안전하고 승인된 NTP 서비스와 동기화하기 위함",
  "threat": "시스템 간 시간 동기화 미흡으로 보안 사고 및 장애 발생 시 로그에 대한 신뢰도 확보 미흡 위험이 존재함",
  "criterion_good": "NTP 및 시각 동기화 설정이 기준에 따라 적용된 경우",
  "criterion_bad": "NTP 및 시각 동기화 설정이 기준에 따라 적용되어 있지 않은 경우",
  "action_method": "NTP 설정 및 동기화 주기 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "NTP 및 시각 동기화 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-65 (2026 ver.)"
  ]
}
JSON
}

_u_65_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령:"
        echo "##  chrony.conf pool/server 설정"
        _dump_path "/etc/chrony.conf" "^[[:space:]]*(pool|server)[[:space:]]+[^#[:space:]]"
        echo
        echo "## chronyd 서비스 상태"
        echo "is-enabled chronyd: $(systemctl is-enabled chronyd 2>&1)"
        echo "is-active  chronyd: $(systemctl is-active  chronyd 2>&1)"
        echo
        echo "## chronyc sources (NTP 서버 도달 상태)"
        if command -v chronyc >/dev/null 2>&1; then
            chronyc sources 2>&1 | head -20 || true
        else
            echo "(chronyc 명령 없음)"
        fi
        echo
        echo "## timedatectl NTP 동기화 상태"
        if command -v timedatectl >/dev/null 2>&1; then
            timedatectl 2>&1 | head -15 || true
        else
            echo "(timedatectl 명령 없음)"
        fi
    } | _evidence_capture "$label"
}


_u65_conf()    { printf '/etc/chrony.conf'; }
_u65_svc()     { printf 'chronyd'; }

# NTP_SERVERS 콤마 리스트 → 배열
_u65_ntp_servers() {
    local IFS=','
    read -r -a _ntp_arr <<< "${NTP_SERVERS:-}"
    printf '%s\n' "${_ntp_arr[@]}"
}

# chronyd 서비스가 active 인지 확인
_u65_svc_active() {
    systemctl is-active chronyd >/dev/null 2>&1
}

# timedatectl 로 NTP 동기화 활성 여부 확인
_u65_ntp_synced() {
    local val
    val=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null \
          || timedatectl 2>/dev/null | awk -F: '/NTP synchronized/{gsub(/ /,"",$2); print $2}')
    [[ "$val" == "yes" ]]
}

# chronyd active 기준 check.
# 판정 기준 (폐쇄망 고려):
#   양호 — chronyd active + chrony.conf 에 pool/server 설정이 존재 (실제 동기화 여부는 네트워크 문제)
#   취약 — chrony 미설치 / chronyd 비활성 / chrony.conf 에 pool/server 설정 없음
h_U_65_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_65_capture_state "$KISA_PHASE"
    fi

    if ! command -v chronyc >/dev/null 2>&1; then
        printf '취약 — chrony 패키지 미설치'
        return 1
    fi

    local svc_status enabled_status
    svc_status=$(systemctl is-active chronyd 2>/dev/null || printf 'inactive')
    enabled_status=$(systemctl is-enabled chronyd 2>/dev/null || printf 'disabled')

    if [[ "$svc_status" != "active" ]]; then
        printf '취약 — chronyd 비활성(%s/%s)' "$svc_status" "$enabled_status"
        return 1
    fi

    # chrony.conf 에 pool/server 설정 존재 여부 (주석 제외)
    local conf; conf="$(_u65_conf)"
    local cfg_count=0
    if [[ -f "$conf" ]]; then
        cfg_count=$(grep -cE '^[[:space:]]*(pool|server)[[:space:]]+[^#[:space:]]' "$conf" 2>/dev/null || printf '0')
        [[ -z "$cfg_count" ]] && cfg_count=0
    fi

    if (( cfg_count == 0 )); then
        printf '취약 — chronyd 활성이나 chrony.conf 에 pool/server 설정 없음'
        return 1
    fi

    # NTP_SERVERS 가 audit.conf 로 명시된 경우, 모든 명시 서버가 chrony.conf 에 등록되어 있어야 양호.
    # 하나라도 누락되면 취약 → apply 단계가 실행되어 사용자 입력값이 반영됨.
    if [[ -n "${NTP_SERVERS:-}" ]]; then
        local _ntp_arr
        IFS=',' read -r -a _ntp_arr <<< "$NTP_SERVERS"
        local missing=()
        local s
        for s in "${_ntp_arr[@]}"; do
            s="${s// /}"
            [[ -z "$s" ]] && continue
            grep -qE "^[[:space:]]*(pool|server)[[:space:]]+${s//./\\.}([[:space:]]|$)" "$conf" 2>/dev/null \
                || missing+=("$s")
        done
        if (( ${#missing[@]} > 0 )); then
            printf '취약 — NTP_SERVERS 명시되었으나 chrony.conf 에 누락: %s' "${missing[*]}"
            return 1
        fi
    fi

    # 참고: chronyc sources 도달/NTP 동기화 상태
    local src_count ntp_sync
    src_count=$(chronyc sources 2>/dev/null | awk '/^\^[*+?x#-]/{c++} END{print c+0}')
    [[ -z "$src_count" ]] && src_count=0
    if _u65_ntp_synced; then ntp_sync="synced"; else ntp_sync="not-synced"; fi

    printf '양호 — chronyd 활성, NTP 서버 %d개 설정 (sources=%d, sync=%s)' "$cfg_count" "$src_count" "$ntp_sync"
    return 0
}

h_U_65_apply() {
    local conf; conf="$(_u65_conf)"
    local svc;  svc="$(_u65_svc)"

    # NTP_SERVERS 빈값이면 자동 적용 안 함 (사이트별 NTP 서버를 강제로 박지 않음)
    if [[ -z "${NTP_SERVERS:-}" ]]; then
        printf '수동 조치 필요 — NTP_SERVERS 빈값\n조치: audit.conf 의 NTP_SERVERS 에 서버 입력 후 재실행하거나 chrony.conf 수동 설정 필요'
        return 2
    fi

    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) %s 의 기존 pool/server 라인 주석 처리 후 NTP_SERVERS(%s) 추가; chronyd enable+restart (deferred)' \
               "$conf" "$NTP_SERVERS"
        return 0
    fi

    # chrony 패키지 확인
    if ! command -v chronyc >/dev/null 2>&1; then
        printf '수동 조치 필요 — chrony 패키지 미설치\n조치: "dnf install -y chrony" 후 재실행 필요'
        return 2
    fi

    [[ -f "$conf" ]] || { printf '조치 실패 — chrony.conf 파일 없음: %s' "$conf"; return 1; }

    backup_file "$conf"

    # awk: 기존 ^pool / ^server 라인 주석 처리 후 파일 끝에 새 서버 추가
    local tmp; tmp="$KISA_TMP_DIR/tmp/u65.$$.$RANDOM"
    mkdir -p "$(dirname "$tmp")"

    # 먼저 기존 pool/server 라인 주석 처리
    local om ou og
    om=$(stat -c '%a' "$conf" 2>/dev/null || printf '644')
    ou=$(stat -c '%u' "$conf" 2>/dev/null || printf '0')
    og=$(stat -c '%g' "$conf" 2>/dev/null || printf '0')

    awk '
        /^[[:space:]]*(pool|server)[[:space:]]/ {
            print "# [KISA U-65] " $0
            next
        }
        { print }
    ' "$conf" > "$tmp"

    # NTP_SERVERS 추가 (중복 방지: 이미 kisa 마커 라인 존재 시 skip)
    {
        printf '\n# [KISA U-65] NTP 서버 설정\n'
        while IFS= read -r srv; do
            [[ -z "$srv" ]] && continue
            printf 'server %s iburst\n' "$srv"
        done < <(_u65_ntp_servers)
    } >> "$tmp"

    mv -f "$tmp" "$conf"
    chmod "$om" "$conf" 2>/dev/null || true
    chown "$ou:$og" "$conf" 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && restorecon "$conf" 2>/dev/null || true

    # idempotent 보호: 이미 kisa 마커 라인이 두 번 이상 추가되면 중복 제거
    # (연속 실행 시 주석 처리된 라인은 재처리 안 됨 — 이미 ^# 로 시작)

    # chronyd 활성화
    systemctl unmask chronyd >/dev/null 2>&1 || true
    systemctl enable chronyd >/dev/null 2>&1 || true

    # restart 큐잉 (서비스 재시작은 kisa-audit.sh 가 flush 시 실행)
    _queue_service_op restart "$svc"
    _queue_rollback   systemctl_restart "$svc"

    printf '조치 완료 — chrony.conf 기존 pool/server 주석 처리 후 NTP_SERVERS(%s) 추가; chronyd enable + restart 지연' \
           "$NTP_SERVERS"
}
