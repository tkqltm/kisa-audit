#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-01: root 계정 원격 접속 제한 (중요도: 상)
# KISA 가이드: /etc/ssh/sshd_config 의 PermitRootLogin = no.
#
# Rocky 8  : /etc/ssh/sshd_config 에 Include 지시자 없음 → main 파일만 수정.
# Rocky 9/10: /etc/ssh/sshd_config 이 'Include /etc/ssh/sshd_config.d/*.conf' 로
#            drop-in 을 로드. sshd 는 first-match-wins 이므로, main 만 고쳐도
#            drop-in 이 PermitRootLogin yes 를 박아놨으면 무효. → 00-kisa-hardening.conf
#            (알파벳 최우선) 로 override.
#
# 조치 전략 (공통 → 조건부):
#   0) ADMIN_USER 지정 시:
#        - 계정이 없으면 useradd -m -s /bin/bash 로 자동 생성 (rollback: userdel -r)
#        - ADMIN_USER_PUBKEY 지정 시 ~/.ssh/authorized_keys 설치 (0600)
#        - KISA_ADMIN_USER_PASSWORD (env) 지정 시 chpasswd 로 비번 설정
#        - pubkey/password 모두 부재면 manual 반환 (관리자 봉쇄 방지)
#        - wheel 편입 + %wheel sudoers 활성화
#   1) main sshd_config 의 비주석 PermitRootLogin 라인을 target 값으로 sync
#   2) Include 지시자 존재 & /etc/ssh/sshd_config.d 디렉터리 존재 시에만:
#        - drop-in override 파일 생성
#        - 다른 drop-in 들의 PermitRootLogin 라인 주석 처리
#   3) sshd -t 검증 실패 시 모든 변경 즉시 restore_file 로 원복
#   4) sshd reload 는 _queue_service_op 로 지연 (리포트 렌더링 후 실행)

h_U_01_meta() {
    cat <<'JSON'
{
  "code": "U-01",
  "title": "root 계정 원격 접속 제한",
  "severity": "상",
  "category": "계정 관리",
  "purpose": "관리자 계정 탈취로 인한 시스템 장악을 방지하기 위해 외부 비인가자의 root 계정 접근 시도를 원천적으로 차단하기 위함",
  "threat": "root 계정은 운영체제의 모든 기능을 설정 및 변경이 가능하여(프로세스, 커널 변경 등) root 계정을 탈취하여 외부에서 원격을 이용한 시스템 장악 및 각종 공격으로(무차별 대입 공격, 사전 대입 공격 등) 인한 root 계정 사용 불가 위험이 존재함",
  "criterion_good": "원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우",
  "criterion_bad": "원격터미널 서비스 사용 시 root 직접 접속을 허용한 경우",
  "action_method": "원격 접속 시 root 계정으로 접속할 수 없도록 파일 내용 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "시스템 정책에 root 계정의 원격터미널 접속 차단 설정이 적용 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-01 (2026 ver.)"
  ]
}
JSON
}

_u_01_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: sshd PermitRootLogin 설정 (root 원격 SSH 접속 제한)"
        echo
        echo "## sshd -T effective PermitRootLogin 값"
        if command -v sshd >/dev/null 2>&1; then
            sshd -T 2>/dev/null | grep -i '^permitrootlogin' || echo "(sshd -T 실패)"
        else
            echo "(sshd 명령 없음)"
        fi
        echo
        echo "## /etc/ssh/sshd_config PermitRootLogin 라인"
        if [[ -f /etc/ssh/sshd_config ]]; then
            grep -nE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config 2>&1 || echo "(main config: PermitRootLogin 라인 없음)"
        fi
        echo
        echo "## /etc/ssh/sshd_config.d/ drop-in PermitRootLogin"
        if [[ -d /etc/ssh/sshd_config.d ]]; then
            grep -rnE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config.d/ 2>/dev/null || echo "(drop-in: PermitRootLogin 라인 없음)"
        fi
        echo
        echo "## sshd 서비스 상태"
        echo "is-enabled sshd: $(systemctl is-enabled sshd 2>&1)"
        echo "is-active  sshd: $(systemctl is-active  sshd 2>&1)"
    } | _evidence_capture "$label"
}


_u01_main_conf() { printf '/etc/ssh/sshd_config'; }
_u01_override()  { printf '/etc/ssh/sshd_config.d/00-kisa-hardening.conf'; }

# main sshd_config 이 Include 지시자로 drop-in 디렉터리를 로드하는가?
_u01_has_include() {
    local main; main="$(_u01_main_conf)"
    [[ -r "$main" ]] || return 1
    grep -qE '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$main"
}

# list all drop-in files (may be empty)
_u01_dropins() {
    local d=/etc/ssh/sshd_config.d
    [[ -d "$d" ]] || return 0
    find "$d" -maxdepth 1 -name '*.conf' -type f 2>/dev/null | sort
}

# compute effective PermitRootLogin value (lowercased); echoes one of:
#   no | prohibit-password | forced-commands-only | yes | UNKNOWN
_u01_effective_value() {
    local v
    v=$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print tolower($2); exit}')
    if [[ -n "$v" ]]; then
        printf '%s' "$v"
        return 0
    fi
    # fallback: first-match scan across main + drop-ins (matches sshd rule)
    local f first=""
    while IFS= read -r f; do
        [[ -r "$f" ]] || continue
        local line
        line=$(awk 'BEGIN{IGNORECASE=1}
                    /^[[:space:]]*#/ {next}
                    tolower($1)=="permitrootlogin"{print tolower($2); exit}' "$f")
        if [[ -n "$line" ]]; then first="$line"; break; fi
    done < <(printf '%s\n' "$(_u01_main_conf)"; _u01_dropins)
    printf '%s' "${first:-UNKNOWN}"
}

h_U_01_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_01_capture_state "$KISA_PHASE"
    fi

    local main_f; main_f="$(_u01_main_conf)"
    if [[ ! -r "$main_f" ]]; then
        printf 'sshd_config 읽기 실패(%s)' "$main_f"
        return 2
    fi
    local val; val="$(_u01_effective_value)"
    case "$val" in
        no|prohibit-password|forced-commands-only)
            printf '양호 — PermitRootLogin=%s (effective), root 직접 원격 접속 차단됨' "$val"
            return 0
            ;;
        UNKNOWN)
            printf '취약 — PermitRootLogin 설정 부재(sshd 기본값 prohibit-password 이나 명시 권고)'
            return 1
            ;;
        yes|*)
            printf '취약 — PermitRootLogin=%s (effective), root 직접 원격 접속 허용됨' "$val"
            return 1
            ;;
    esac
}

_u01_has_alt_admin() {
    # root 외에 SSH 로그인 가능 + sudo 가능한 계정이 있는지 검증.
    # 없으면 PermitRootLogin=no 적용 시 관리자 봉쇄.
    local shadow=/etc/shadow
    local user _ uid _ _ home shell pass
    local alt=""
    # wheel 그룹 멤버 목록
    local wheel_members
    wheel_members=$(getent group wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')
    [[ -z "$wheel_members" ]] && wheel_members=""

    # sudoers 및 sudoers.d 에서 허용 계정 수집 (단순 파싱)
    local sudo_users
    sudo_users=$(grep -hE '^[^#%]*[[:space:]]+ALL[[:space:]]*=.*ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
                 | awk '{print $1}' | grep -v '^%' | grep -v '^Defaults' | sort -u)

    while IFS=: read -r user _ uid _ _ home shell; do
        [[ -n "$shell" ]] || continue
        (( uid >= 1000 )) || continue
        # 로그인 가능 셸 (nologin/false 제외)
        case "$shell" in
            */nologin|*/false|''|/sbin/nologin|/usr/sbin/nologin) continue ;;
        esac
        # password 설정 또는 authorized_keys 존재
        pass=$(awk -F: -v u="$user" '$1==u{print $2}' "$shadow" 2>/dev/null)
        local has_cred=0
        if [[ -n "$pass" && "$pass" != "*" && "$pass" != "!" && "$pass" != "!!" && "$pass" != "!"* ]]; then
            has_cred=1
        fi
        if [[ -r "$home/.ssh/authorized_keys" ]] && [[ -s "$home/.ssh/authorized_keys" ]]; then
            has_cred=1
        fi
        (( has_cred == 1 )) || continue
        # sudo 가능 여부
        local is_admin=0
        [[ " $wheel_members " == *" $user "* ]] && is_admin=1
        [[ -n "$sudo_users" ]] && echo "$sudo_users" | grep -qx "$user" && is_admin=1
        if (( is_admin )); then
            alt="$user"
            break
        fi
    done < /etc/passwd
    [[ -n "$alt" ]] && { printf '%s' "$alt"; return 0; }
    return 1
}

h_U_01_apply() {
    local main_f;   main_f="$(_u01_main_conf)"
    local ovr;      ovr="$(_u01_override)"
    local target="${SSH_PERMIT_ROOT_LOGIN:-no}"
    local use_dropin=0
    # drop-in 방식은 Include 지시자 존재 + sshd_config.d 에 이미 다른 .conf 파일이 있을 때만 사용.
    # 빈 디렉터리(또는 우리 파일만 있는 경우)면 sshd_config 단일 파일 수정이 더 명확함.
    if _u01_has_include && [[ -d /etc/ssh/sshd_config.d ]]; then
        local _other_confs
        _other_confs=$(find /etc/ssh/sshd_config.d -maxdepth 1 -name '*.conf' -type f \
                           ! -name '00-kisa-hardening.conf' 2>/dev/null | wc -l)
        (( _other_confs > 0 )) && use_dropin=1
    fi

    # 관리자 봉쇄 방지: root 외 sudo 가능한 일반계정이 없으면 skip 처리
    local alt_admin="" admin_note=""
    local is_dry_run=0
    [[ "${1:-}" == "--dry-run" ]] && is_dry_run=1
    if [[ "$target" != "yes" && "${FORCE_SSH_ROOT_BLOCK:-0}" != "1" ]]; then

        # (A) ADMIN_USER 지정: 정책
        #   - 기존 계정: wheel 편입 + sudoers 활성화만. 비번 미변경(보존).
        #                ADMIN_USER_PUBKEY 지정 시 authorized_keys append.
        #   - 신규 생성: useradd + (비번/공개키 주입) + wheel 편입 + sudoers 활성화.
        #                비번/공개키 모두 없으면 manual (로그인 불가 계정 생성 금지).
        if [[ -n "${ADMIN_USER:-}" ]]; then
            # 계정 이름 유효성 (POSIX: [a-z_][a-z0-9_-]*, 32자 이내)
            if ! [[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
                printf '조치 실패 — ADMIN_USER=%s 형식 오류 (POSIX 계정명 규칙 위반)' "$ADMIN_USER"
                return 1
            fi

            local have_pubkey=0 have_password=0 user_exists=0
            [[ -n "${ADMIN_USER_PUBKEY:-}"   ]] && have_pubkey=1
            [[ -n "${ADMIN_USER_PASSWORD:-}" ]] && have_password=1
            id -u "$ADMIN_USER" >/dev/null 2>&1 && user_exists=1

            # 신규 생성인데 비번/공개키 둘 다 없음 → manual (로그인 불가)
            if (( user_exists == 0 )) && (( have_pubkey == 0 )) && (( have_password == 0 )); then
                if (( is_dry_run )); then
                    printf '(dry-run) 수동 조치 필요 — [MANUAL] ADMIN_USER=%s 계정 없음 + 크레덴셜 미지정\n조치: ADMIN_USER_PASSWORD 또는 ADMIN_USER_PUBKEY 제공 후 재실행 (로그인 불가 계정 생성 금지)' "$ADMIN_USER"
                    return 2
                fi
                printf '수동 조치 필요 — ADMIN_USER=%s 계정 없음 + 크레덴셜 미지정\n조치: ADMIN_USER_PASSWORD 또는 ADMIN_USER_PUBKEY 제공 후 재실행' "$ADMIN_USER"
                return 2
            fi

            # 기존 계정인데 로그인 크레덴셜(pass/authorized_keys) 전혀 없는 방치 계정 → manual
            # (이 경우는 wheel 에 넣어도 SSH 로그인 불가)
            if (( user_exists == 1 )); then
                local au_home_c au_pass_c have_exist_cred=0
                au_home_c=$(getent passwd "$ADMIN_USER" | awk -F: '{print $6}')
                au_pass_c=$(awk -F: -v u="$ADMIN_USER" '$1==u{print $2}' /etc/shadow 2>/dev/null)
                if [[ -n "$au_pass_c" && "$au_pass_c" != "*" && "$au_pass_c" != "!" && "$au_pass_c" != "!!" && "$au_pass_c" != "!"* ]]; then
                    have_exist_cred=1
                fi
                if [[ -s "$au_home_c/.ssh/authorized_keys" ]]; then
                    have_exist_cred=1
                fi
                # pubkey 를 새로 주입할 예정이면 크레덴셜 부재여도 OK (주입 후 로그인 가능)
                if (( have_exist_cred == 0 )) && (( have_pubkey == 0 )); then
                    if (( is_dry_run )); then
                        printf '(dry-run) 수동 조치 필요 — [MANUAL] ADMIN_USER=%s 존재하나 로그인 크레덴셜 없음\n조치: ADMIN_USER_PUBKEY 로 공개키 설치 또는 수동 passwd 설정 후 재실행 (정책상 기존 계정 비번 미변경)' "$ADMIN_USER"
                        return 2
                    fi
                    printf '수동 조치 필요 — ADMIN_USER=%s 크레덴셜 없음(기존 계정)\n조치: 공개키 설치 또는 수동 passwd 후 재실행' "$ADMIN_USER"
                    return 2
                fi
            fi

            # ----- dry-run: 변경 없이 플랜만 -----
            if (( is_dry_run )); then
                local notes=()
                if (( user_exists == 0 )); then
                    notes+=("useradd -m -s /bin/bash $ADMIN_USER")
                    (( have_password == 1 )) && notes+=("chpasswd 비번 설정")
                    (( have_pubkey   == 1 )) && notes+=("authorized_keys 설치")
                else
                    notes+=("계정 이미 존재 (비번 미변경)")
                    (( have_pubkey   == 1 )) && notes+=("authorized_keys append")
                fi
                if id -nG "$ADMIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx wheel; then
                    notes+=("이미 wheel 소속")
                else
                    notes+=("wheel 편입")
                fi
                admin_note="ADMIN_USER=$ADMIN_USER → $(IFS='; '; printf '%s' "${notes[*]}")"
                alt_admin="$ADMIN_USER"
            else
                # ----- 실제 apply -----
                # 1) 신규 생성 경로 (계정 없음)
                if (( user_exists == 0 )); then
                    backup_file /etc/passwd
                    backup_file /etc/shadow
                    backup_file /etc/group
                    backup_file /etc/gshadow
                    if ! useradd -m -s /bin/bash "$ADMIN_USER" 2>/dev/null; then
                        printf '조치 실패 — useradd %s 실패' "$ADMIN_USER"
                        return 1
                    fi
                    # rollback: 이 핸들러가 만든 계정+홈 제거 + orphan 잔존파일 정리
                    # Rocky 10 sudo 는 /var/db/sudo/lectured/<UID> 로 기록 (구버전은 <username>)
                    # → 둘 다 지운다. userdel -r 은 /var/spool/mail/<user> 도 종종 남김.
                    local _rb_uid
                    _rb_uid=$(id -u "$ADMIN_USER" 2>/dev/null || printf '0')
                    _queue_rollback exec "pkill -KILL -u $ADMIN_USER 2>/dev/null; sleep 1; userdel -rf $ADMIN_USER 2>/dev/null; rm -rf /var/db/sudo/lectured/$ADMIN_USER /var/db/sudo/lectured/$_rb_uid /var/spool/mail/$ADMIN_USER /var/spool/cron/$ADMIN_USER /home/$ADMIN_USER"
                    admin_note="ADMIN_USER=$ADMIN_USER 신규 생성"

                    # 비번 설정 (신규 계정 한정)
                    if (( have_password == 1 )); then
                        printf '%s:%s\n' "$ADMIN_USER" "$ADMIN_USER_PASSWORD" \
                            | chpasswd 2>/dev/null \
                            || { printf '조치 실패 — chpasswd 실패 (ADMIN_USER=%s)' "$ADMIN_USER"; return 1; }
                        admin_note="${admin_note}; 비번 설정"
                    fi
                else
                    admin_note="ADMIN_USER=$ADMIN_USER 기존 계정 (비번 미변경)"
                fi

                local au_home
                au_home=$(getent passwd "$ADMIN_USER" | awk -F: '{print $6}')
                [[ -z "$au_home" ]] && au_home="/home/$ADMIN_USER"

                # 2) 공개키 설치 (신규·기존 모두 append, idempotent)
                if (( have_pubkey == 1 )); then
                    local ssh_dir="$au_home/.ssh"
                    local auth_file="$ssh_dir/authorized_keys"
                    mkdir -p "$ssh_dir"
                    backup_file "$auth_file"
                    if [[ -f "$auth_file" ]] && grep -qxF "$ADMIN_USER_PUBKEY" "$auth_file"; then
                        admin_note="${admin_note}; 공개키 이미 설치"
                    else
                        printf '%s\n' "$ADMIN_USER_PUBKEY" >> "$auth_file"
                        admin_note="${admin_note}; 공개키 설치"
                    fi
                    chmod 0700 "$ssh_dir"
                    chmod 0600 "$auth_file"
                    chown -R "$ADMIN_USER:$(id -gn "$ADMIN_USER")" "$ssh_dir" 2>/dev/null || true
                    command -v restorecon >/dev/null 2>&1 && restorecon -R "$ssh_dir" 2>/dev/null || true
                fi

                # 3) wheel 편입 (idempotent)
                if id -nG "$ADMIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx wheel; then
                    admin_note="${admin_note}; 이미 wheel"
                else
                    backup_file /etc/group
                    backup_file /etc/gshadow
                    if usermod -aG wheel "$ADMIN_USER" 2>/dev/null; then
                        admin_note="${admin_note}; wheel 편입"
                    else
                        printf '조치 실패 — ADMIN_USER=%s wheel 추가 실패' "$ADMIN_USER"
                        return 1
                    fi
                fi

                # 4) %wheel sudoers 활성화 (Rocky 기본: 주석 상태일 수 있음)
                if grep -qE '^[[:space:]]*#[[:space:]]*%wheel[[:space:]]+ALL=\(ALL\)[[:space:]]+ALL' /etc/sudoers 2>/dev/null; then
                    backup_file /etc/sudoers
                    local sudo_tmp="$KISA_TMP_DIR/tmp/sudoers.u01.$$"
                    mkdir -p "$(dirname "$sudo_tmp")"
                    sed -E 's/^([[:space:]]*)#[[:space:]]*(%wheel[[:space:]]+ALL=\(ALL\)[[:space:]]+ALL)/\1\2/' /etc/sudoers > "$sudo_tmp"
                    if visudo -cf "$sudo_tmp" >/dev/null 2>&1; then
                        install -m 0440 -o root -g root "$sudo_tmp" /etc/sudoers
                        admin_note="${admin_note}; %wheel sudoers 활성화"
                    else
                        log_warn "U-01: sudoers 편집 후 visudo -cf 검증 실패 — sudoers 변경 건너뜀"
                    fi
                    rm -f "$sudo_tmp"
                fi

                alt_admin="$ADMIN_USER"
            fi
        fi

        # (B) ADMIN_USER 미지정 → 기존 wheel 멤버 자동 탐색
        if [[ -z "$alt_admin" ]]; then
            alt_admin=$(_u01_has_alt_admin 2>/dev/null || true)
        fi

        if [[ -z "$alt_admin" ]]; then
            if (( is_dry_run )); then
                printf '(dry-run) 수동 조치 필요 — [MANUAL] root 외 sudo 가능한 일반계정 부재(PermitRootLogin=no 적용 시 원격 관리자 봉쇄 위험)\n조치: audit.conf 의 ADMIN_USER(+ADMIN_USER_PUBKEY 또는 KISA_ADMIN_USER_PASSWORD) 지정 후 재실행, 또는 FORCE_SSH_ROOT_BLOCK=1 로 강제 적용'
                return 2
            fi
            printf '수동 조치 필요 — root 외 sudo 가능한 일반계정 부재, PermitRootLogin=%s 적용 보류(관리자 봉쇄 방지)\n조치: audit.conf 의 ADMIN_USER(+PUBKEY/PASSWORD) 지정 후 재실행, 또는 FORCE_SSH_ROOT_BLOCK=1 로 강제 적용' "$target"
            return 2
        fi
    fi

    if [[ "${1:-}" == "--dry-run" ]]; then
        local extra=""; [[ -n "$admin_note" ]] && extra=" [${admin_note}]"
        if (( use_dropin )); then
            printf '(dry-run) PermitRootLogin=%s 적용 예정 (sshd 검증 후 reload 지연) [대체 관리자: %s]%s' \
                   "$target" "${alt_admin:-<FORCE>}" "$extra"
        else
            printf '(dry-run) PermitRootLogin=%s 적용 예정 (sshd 검증 후 reload 지연) [대체 관리자: %s]%s' "$target" "${alt_admin:-<FORCE>}" "$extra"
        fi
        return 0
    fi

    [[ -f "$main_f" ]] || { printf '조치 실패 — sshd_config 없음: %s' "$main_f"; return 1; }

    local modified=()

    # 1) sync main sshd_config
    backup_file "$main_f"
    modified+=("$main_f")
    if grep -qE '^[[:space:]]*PermitRootLogin[[:space:]]' "$main_f"; then
        set_kv "$main_f" "PermitRootLogin" "PermitRootLogin ${target}"
    else
        printf '\n# [KISA U-01]\nPermitRootLogin %s\n' "$target" >> "$main_f"
    fi

    # 2) drop-in override (Rocky 9/10 only)
    if (( use_dropin )); then
        backup_file "$ovr"                # records ABSENT if not present
        modified+=("$ovr")
        mkdir -p "$(dirname "$ovr")"
        install -m 0600 -o root -g root /dev/null "$ovr"
        printf '# Managed by KISA U-01 (kisa-audit). Do not edit manually.\nPermitRootLogin %s\n' "$target" > "$ovr"
        command -v restorecon >/dev/null 2>&1 && restorecon "$ovr" 2>/dev/null || true

        local f tmp om ou og
        while IFS= read -r f; do
            [[ "$f" == "$ovr" ]] && continue
            [[ -f "$f" ]] || continue
            if grep -qE '^[[:space:]]*PermitRootLogin[[:space:]]' "$f"; then
                backup_file "$f"
                modified+=("$f")
                om=$(stat -c '%a' "$f" 2>/dev/null || true)
                ou=$(stat -c '%u' "$f" 2>/dev/null || true)
                og=$(stat -c '%g' "$f" 2>/dev/null || true)
                tmp="$KISA_TMP_DIR/tmp/u01.$$.$RANDOM"
                awk '
                    /^[[:space:]]*PermitRootLogin[[:space:]]/ { print "# [KISA U-01] " $0; next }
                    { print }
                ' "$f" > "$tmp"
                mv -f "$tmp" "$f"
                [[ -n "$om" ]] && chmod "$om" "$f" 2>/dev/null || true
                [[ -n "$ou" && -n "$og" ]] && chown "$ou:$og" "$f" 2>/dev/null || true
                command -v restorecon >/dev/null 2>&1 && restorecon "$f" 2>/dev/null || true
            fi
        done < <(_u01_dropins)
    fi

    # 3) validate
    if ! sshd -t 2>/dev/null; then
        local m
        for m in "${modified[@]}"; do restore_file "$m" || true; done
        printf '조치 실패 — sshd -t 검증 실패, 모든 변경 원복 완료'
        return 1
    fi

    # 4) DEFER sshd reload. Calling systemctl here would immediately drop the admin
    #    SSH session when PermitRootLogin=no takes effect. kisa-audit.sh invokes
    #    _flush_service_queue() AFTER all handlers and report rendering.
    _queue_service_op reload sshd
    _queue_rollback   systemctl_reload sshd

    local extra=""; [[ -n "$admin_note" ]] && extra=" [${admin_note}]"
    if (( use_dropin )); then
        printf '조치 완료 — PermitRootLogin=%s 적용 (effective=%s); sshd reload 지연%s' \
               "$target" "$(_u01_effective_value)" "$extra"
    else
        printf '조치 완료 — PermitRootLogin=%s 적용 (effective=%s); sshd reload 지연%s' \
               "$target" "$(_u01_effective_value)" "$extra"
    fi
}
