#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# deploy.sh — targets.conf 에 등록된 Rocky 서버에 kisa-audit 배포·실행·report.html 회수.
#
# 사용법:
#   ./deploy.sh push                       # 스크립트만 배포 (scp + 압축해제)
#   ./deploy.sh check                      # 원격 check → 콘솔 결과(console.txt) 회수
#   ./deploy.sh apply [--dry-run]          # 원격 apply → report.html + console.txt 회수
#   ./deploy.sh rollback                   # 원격 rollback (시스템 전수 *.kisa.bak 복원)
#
# 사전 준비:
#   1) 스크립트와 같은 디렉터리에 targets.conf 작성 (targets.conf.example 참고)
#      # host  port  user  password
#      <대상 IP/호스트>  <SSH 포트>  <계정>  <비밀번호>
#   2) 관리 PC 에 sshpass 설치 (dnf install -y sshpass)
#
# 회수 위치: ./reports/<timestamp>-<mode>/<host>/  (apply: report.html + console.txt, check: console.txt)

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_FILE="$SCRIPT_DIR/targets.conf"
REPORT_DIR_DEFAULT="$SCRIPT_DIR/reports"
REMOTE_DIR="/kisa-audit"

C_R=$'\e[0m'; C_CY=$'\e[36m'; C_Y=$'\e[33m'; C_RED=$'\e[31m'
log()  { printf '%b\n' "${C_CY}[deploy]${C_R} $*"; }
warn() { printf '%b\n' "${C_Y}[deploy]${C_R} $*"; }
die()  { printf '%b\n' "${C_RED}[deploy]${C_R} $*" >&2; exit 1; }

command -v sshpass >/dev/null 2>&1 || die "sshpass 필요 — 관리 PC에 설치 후 재실행."

_load_targets() {
    [[ -f "$TARGETS_FILE" ]] || die "$TARGETS_FILE 없음. targets.conf.example 를 복사·편집 후 재실행하세요."
    local rows
    rows=$(python3 -c '
import sys, re
rows = []
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split(None, 3)
    if len(parts) < 4:
        continue
    host, port, user, pw = parts
    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$", host)
    if m:
        prefix, start, end = m.groups()
        for i in range(int(start), int(end) + 1):
            rows.append(f"{prefix}.{i} {port} {user} {pw}")
    else:
        rows.append(f"{host} {port} {user} {pw}")
for r in rows:
    print(r)
' < "$TARGETS_FILE" || true)
    [[ -z "$rows" ]] && die "$TARGETS_FILE 에 유효한 대상 라인이 없습니다."
    printf '%s\n' "$rows"
}

_ssh() {
    local host="$1" port="$2" user="$3" pw="$4"; shift 4
    sshpass -p "$pw" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -p "$port" "$user@$host" "$@"
}
_scp_push() {
    local host="$1" port="$2" user="$3" pw="$4" src="$5" dst="$6"
    sshpass -p "$pw" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$port" "$src" "$user@$host:$dst"
}
_scp_pull() {
    local host="$1" port="$2" user="$3" pw="$4" src="$5" dst="$6"
    sshpass -p "$pw" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$port" "$user@$host:$src" "$dst"
}

# audit.conf 가 apply 로 root SSH 차단(PermitRootLogin=no) 시킨 경우, deploy.sh 가
# rollback / report.html 회수 시 root 로그인 못 함 → audit.conf 의 ADMIN_USER/PASSWORD
# 로 fallback 한다. ADMIN_USER 가 빈값이면 fallback 없음(원래 동작).
_load_admin_creds() {
    [[ -f "$SCRIPT_DIR/config/audit.conf" ]] || return 1
    # subshell 에서 source 한 뒤 변수 추출 (전역 오염 방지)
    local out
    out=$(bash -c "source '$SCRIPT_DIR/config/audit.conf' 2>/dev/null; \
                   printf '%s\n%s\n%s\n' \"\${ADMIN_USER:-}\" \"\${ADMIN_USER_PASSWORD:-}\" \"\${SSH_PORT:-}\"")
    local au ap sp
    au=$(printf '%s' "$out" | sed -n '1p')
    ap=$(printf '%s' "$out" | sed -n '2p')
    sp=$(printf '%s' "$out" | sed -n '3p')
    [[ -n "$au" && -n "$ap" ]] || return 1
    printf '%s\n%s\n%s\n' "$au" "$ap" "$sp"
}

# root 시도 → 실패 시 admin+sudo fallback 한 _ssh.
# stdin 명령에 sudo 가 필요한 경우 ADMIN_SUDO_PREFIX 환경변수에 prefix 가 들어있다.
_ssh_try_admin() {
    local host="$1" port="$2"; shift 2
    local cmd="$*"
    local creds; creds=$(_load_admin_creds 2>/dev/null) || return 1
    local au ap sp
    au=$(printf '%s' "$creds" | sed -n '1p')
    ap=$(printf '%s' "$creds" | sed -n '2p')
    sp=$(printf '%s' "$creds" | sed -n '3p')

    # 1) 접속 포트 결정 (가벼운 3초 probe로 포트가 살아있는지 검사)
    local connect_port="$port"
    if [[ -n "$sp" && "$sp" != "$port" ]]; then
        if ! sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=3 -p "$port" "$au@$host" 'true' >/dev/null 2>&1; then
            connect_port="$sp"
        fi
    fi

    # 2) 실제 명령 실행 (실제 명령의 exit code에 영향받지 않고 실행 및 출력 캡처)
    local out rc=0
    out=$(sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -p "$connect_port" "$au@$host" \
        "echo '$ap' | sudo -S sh -c \"$cmd\" 2>&1") || rc=$?
    printf '%s\n' "$out"
    return "$rc"
}

_scp_pull_try_admin() {
    local host="$1" port="$2" src="$3" dst="$4"
    local creds; creds=$(_load_admin_creds 2>/dev/null) || return 1
    local au ap sp
    au=$(printf '%s' "$creds" | sed -n '1p')
    ap=$(printf '%s' "$creds" | sed -n '2p')
    sp=$(printf '%s' "$creds" | sed -n '3p')
    
    # 1) 접속 포트 결정 (가벼운 3초 probe로 포트가 살아있는지 검사)
    local connect_port="$port"
    if [[ -n "$sp" && "$sp" != "$port" ]]; then
        if ! sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=3 -p "$port" "$au@$host" 'true' >/dev/null 2>&1; then
            connect_port="$sp"
        fi
    fi

    local tmp_path="/tmp/.kisa-deploy-pull-$$"
    local success=0

    # 2) 임시 파일 복사 및 권한 설정
    if sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -p "$connect_port" "$au@$host" \
        "echo '$ap' | sudo -S sh -c 'cp '$src' $tmp_path && chmod 644 $tmp_path && chown $au $tmp_path'" >/dev/null 2>&1; then
        
        # 3) 파일 SCP 회수
        if sshpass -p "$ap" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -P "$connect_port" "$au@$host:$tmp_path" "$dst" >/dev/null 2>&1; then
            success=1
        fi
        
        # 4) 임시 파일 제거
        sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 -p "$connect_port" "$au@$host" \
            "rm -f $tmp_path" >/dev/null 2>&1 || true
    fi

    if (( success == 1 )); then
        return 0
    fi
    return 1
}

_foreach() {
    local fn="$1"; shift
    local max_jobs=20
    local running=0
    local host port user pw
    while read -r host port user pw; do
        [[ -z "$host" ]] && continue
        (
            local out
            out=$("$fn" "$host" "$port" "$user" "$pw" "$@" 2>&1)
            printf '%s\n' "$out"
        ) &
        running=$((running+1))
        if (( running >= max_jobs )); then
            wait -n 2>/dev/null || wait
            running=$((running-1))
        fi
    done < <(_load_targets)
    wait
}

_make_release() {
    local stage tarball ver
    stage="$(mktemp -d)"
    ver="$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo unknown)"
    # make-release.sh 가 무결성 매니페스트(.integrity.sha256)도 함께 생성한다.
    # 따로 tar 만 따서 보내면 매니페스트 없는 패키지가 되어 원격 _kisa_verify_integrity() 가 실패함.
    "$SCRIPT_DIR/make-release.sh" -o "$stage" >/dev/null 2>&1
    tarball="$stage/kisa-audit-${ver}.tar.gz"
    [[ -f "$tarball" ]] || { warn "make-release.sh 산출물 없음: $tarball"; return 1; }
    printf '%s' "$tarball"
}

push_one() {
    local host="$1" port="$2" user="$3" pw="$4" tarball="$5"
    log "→ push to $host"
    local rc=0
    # Try root first
    _ssh "$host" "$port" "$user" "$pw" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR && chmod 755 $REMOTE_DIR" >/dev/null 2>&1 || rc=$?
    if (( rc == 0 )); then
        _scp_push "$host" "$port" "$user" "$pw" "$tarball" "$REMOTE_DIR/pkg.tar.gz"
        # make-release.sh tarball 은 kisa-audit-<VERSION>/ 최상위 디렉터리 구조라
        # --strip-components=1 로 한 단계 벗겨서 $REMOTE_DIR 직속으로 풀어준다.
        _ssh "$host" "$port" "$user" "$pw" \
            "tar -xzf $REMOTE_DIR/pkg.tar.gz --strip-components=1 -C $REMOTE_DIR && rm -f $REMOTE_DIR/pkg.tar.gz && chmod +x $REMOTE_DIR/kisa-audit.sh"
        # audit.conf 는 check/apply 실행 필수(없으면 원격이 실행 거부). 로컬에 있으면 push,
        # 없으면 원격에서 audit.conf.example 로 기본 생성 → 항상 audit.conf 가 존재하도록 보장.
        if [[ -f "$SCRIPT_DIR/config/audit.conf" ]]; then
            _scp_push "$host" "$port" "$user" "$pw" "$SCRIPT_DIR/config/audit.conf" "$REMOTE_DIR/config/audit.conf"
            _ssh "$host" "$port" "$user" "$pw" "chmod 600 $REMOTE_DIR/config/audit.conf"
        else
            _ssh "$host" "$port" "$user" "$pw" \
                "[ -f $REMOTE_DIR/config/audit.conf ] || cp $REMOTE_DIR/config/audit.conf.example $REMOTE_DIR/config/audit.conf; chmod 600 $REMOTE_DIR/config/audit.conf"
            warn "$host: 로컬 config/audit.conf 없음 → 원격 기본값(audit.conf.example) 으로 실행됨"
        fi
    else
        # root SSH failed, try admin fallback
        warn "$host: root SSH 실패 (rc=$rc) — audit.conf 의 ADMIN_USER 로 push 시도"
        local creds; creds=$(_load_admin_creds 2>/dev/null) || {
            die "$host: root SSH 실패 및 admin 자격증명(audit.conf)을 로드할 수 없어 push 실패."
        }
        local au ap sp
        au=$(printf '%s' "$creds" | sed -n '1p')
        ap=$(printf '%s' "$creds" | sed -n '2p')
        sp=$(printf '%s' "$creds" | sed -n '3p')

        local connect_port="$port"
        if [[ -n "$sp" && "$sp" != "$port" ]]; then
            if ! sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=3 -p "$port" "$au@$host" 'true' >/dev/null 2>&1; then
                connect_port="$sp"
            fi
        fi

        # Push tarball to /tmp
        local tmp_tar="/tmp/.kisa-pkg-$$.tar.gz"
        sshpass -p "$ap" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -P "$connect_port" "$tarball" "$au@$host:$tmp_tar" || die "$host: admin SCP push 실패"

        # Extract using sudo
        local cmd="rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR && chmod 755 $REMOTE_DIR && tar -xzf $tmp_tar --strip-components=1 -C $REMOTE_DIR && rm -f $tmp_tar && chmod +x $REMOTE_DIR/kisa-audit.sh"
        sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 -p "$connect_port" "$au@$host" \
            "echo '$ap' | sudo -S sh -c \"$cmd\"" || die "$host: admin sudo extraction 실패"

        # Push audit.conf if local exists
        if [[ -f "$SCRIPT_DIR/config/audit.conf" ]]; then
            local tmp_conf="/tmp/.kisa-audit-$$.conf"
            sshpass -p "$ap" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -P "$connect_port" "$SCRIPT_DIR/config/audit.conf" "$au@$host:$tmp_conf" || die "$host: admin audit.conf SCP push 실패"
            sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=10 -p "$connect_port" "$au@$host" \
                "echo '$ap' | sudo -S sh -c \"mv $tmp_conf $REMOTE_DIR/config/audit.conf && chmod 600 $REMOTE_DIR/config/audit.conf\"" || die "$host: admin audit.conf mv/chmod 실패"
        else
            sshpass -p "$ap" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=10 -p "$connect_port" "$au@$host" \
                "echo '$ap' | sudo -S sh -c \"[ -f $REMOTE_DIR/config/audit.conf ] || cp $REMOTE_DIR/config/audit.conf.example $REMOTE_DIR/config/audit.conf; chmod 600 $REMOTE_DIR/config/audit.conf\"" || true
            warn "$host: 로컬 config/audit.conf 없음 → 원격 기본값(audit.conf.example) 으로 실행됨"
        fi
    fi
}

run_one() {
    local host="$1" port="$2" user="$3" pw="$4" mode="$5" savebase="$6"; shift 6
    log "→ $mode on $host  (args: ${*:-none})"
    local cmd="cd $REMOTE_DIR && ./kisa-audit.sh $mode $* 2>&1"
    local out rc=0
    out=$(_ssh "$host" "$port" "$user" "$pw" "$cmd" 2>&1) || rc=$?
    if (( rc == 255 || rc == 5 || rc == 6 )); then
        # root SSH 실패 가능성 (apply 후 PermitRootLogin=no) → admin+sudo fallback.
        # rollback 도중 admin 삭제로 세션이 끊겨도 kisa-audit.sh 는 trap '' HUP 으로
        # 끝까지 마치므로 SSH 끊김 자체는 실패가 아님 — 실제 결과는 _verify_post_run 으로 확인.
        warn "$host: root SSH 실패 (rc=$rc) — audit.conf 의 ADMIN_USER 로 fallback 시도"
        local out_fb
        out_fb=$(_ssh_try_admin "$host" "$port" "$cmd" 2>&1 || true)
        if [[ "$out_fb" != *"Connection refused"* ]]; then
            out="$out_fb"
        fi
    fi
    printf '%s\n' "$out" | tail -40
    # 전체 콘솔 결과 저장 (check 는 report.html 미생성 → console.txt 가 결과물)
    if [[ -n "$savebase" ]]; then
        mkdir -p "$savebase/$host"
        printf '%s\n' "$out" > "$savebase/$host/console.txt"
        log "  ← 콘솔 결과 저장: $savebase/$host/console.txt"
    fi
    # mode 별 사후 검증 (rollback 완료 여부 등)
    _verify_post_run "$host" "$port" "$user" "$pw" "$mode"
}

# rollback / apply 가 SSH 세션 단절로 비정상 종료 보고됐어도 실제 작업이 끝났는지
# 직접 확인. rollback 완료 시그널: /var/lib/kisa-audit/rollback.jsonl 가 비었거나 없음.
_verify_post_run() {
    local host="$1" port="$2" user="$3" pw="$4" mode="$5"
    [[ "$mode" == "rollback" ]] || return 0
    # rollback 직후 sshd 가 reload 되어 root SSH 가 부활 가능 — root 먼저 시도.
    local out
    out=$(sshpass -p "$pw" ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -p "$port" "$user@$host" \
        'wc -l /var/lib/kisa-audit/rollback.jsonl 2>/dev/null || echo MISSING' 2>/dev/null) || true
    if [[ -z "$out" ]]; then
        # root 도 안되면 admin 으로 검증 시도 (rollback 이 admin 도 지웠을 수 있어 실패하면 단념).
        out=$(_ssh_try_admin "$host" "$port" \
            'wc -l /var/lib/kisa-audit/rollback.jsonl 2>/dev/null || echo MISSING' 2>/dev/null) || true
    fi
    if [[ "$out" == *"MISSING"* ]] || [[ "${out%% *}" == "0" ]]; then
        log "✓ $host: rollback 완료 검증 (rollback.jsonl 비어있음)"
    else
        warn "$host: rollback 미완료 가능성 — rollback.jsonl: ${out:-검증불가}"
    fi
}

pull_report_one() {
    local host="$1" port="$2" user="$3" pw="$4" dst_base="$5"
    mkdir -p "$dst_base/$host"
    
    # 1) Pull report.html
    local got_html=0
    if _scp_pull "$host" "$port" "$user" "$pw" "$REMOTE_DIR/report.html" "$dst_base/$host/" 2>/dev/null; then
        got_html=1
    elif _scp_pull_try_admin "$host" "$port" "$REMOTE_DIR/report.html" "$dst_base/$host/report.html" 2>/dev/null; then
        got_html=1
    fi
    
    # 2) Pull report.json
    local got_json=0
    if _scp_pull "$host" "$port" "$user" "$pw" "$REMOTE_DIR/report.json" "$dst_base/$host/" 2>/dev/null; then
        got_json=1
    elif _scp_pull_try_admin "$host" "$port" "$REMOTE_DIR/report.json" "$dst_base/$host/report.json" 2>/dev/null; then
        got_json=1
    fi

    if (( got_html )); then
        log "← pulled $host → $dst_base/$host/report.html"
    else
        warn "$host: report.html 회수 실패"
    fi

    if (( got_json )); then
        log "← pulled $host → $dst_base/$host/report.json"
        local docx_renderer="$SCRIPT_DIR/tools/render-docx.py"
        if [[ -f "$docx_renderer" ]]; then
            if python3 "$docx_renderer" "$dst_base/$host/report.json" -o "$dst_base/$host/report.docx" --ip "$host" >/dev/null 2>&1; then
                log "  → generated DOCX: $dst_base/$host/report.docx"
            else
                warn "$host: report.docx 생성 실패"
            fi
        fi
    fi
}

cleanup_one() {
    local host="$1" port="$2" user="$3" pw="$4"
    log "→ cleanup on $host"
    local cmd="rm -rf $REMOTE_DIR"
    local rc=0
    _ssh "$host" "$port" "$user" "$pw" "$cmd" >/dev/null 2>&1 || rc=$?
    if (( rc == 255 || rc == 5 || rc == 6 )); then
        _ssh_try_admin "$host" "$port" "$cmd" >/dev/null 2>&1 || true
    fi
}

cmd_push() {
    local tarball; tarball="$(_make_release)"
    _foreach push_one "$tarball"
    rm -f "$tarball"
}
cmd_check() {
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    local tarball; tarball="$(_make_release)"
    _foreach push_one "$tarball"
    rm -f "$tarball"
    # check 는 report.html 미생성 → 콘솔 결과(console.txt)만 회수
    _foreach run_one check "$REPORT_DIR_DEFAULT/${ts}-check"
    _foreach cleanup_one
    log "check 결과: $REPORT_DIR_DEFAULT/${ts}-check/<host>/console.txt"
}
cmd_apply() {
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    local base="$REPORT_DIR_DEFAULT/${ts}-apply"
    local tarball; tarball="$(_make_release)"
    _foreach push_one "$tarball"
    rm -f "$tarball"
    _foreach run_one apply "$base" "$@"
    _foreach pull_report_one "$base"
    _foreach cleanup_one
}
cmd_rollback() {
    local tarball; tarball="$(_make_release)"
    _foreach push_one "$tarball"
    rm -f "$tarball"
    _foreach run_one rollback ""
    _foreach cleanup_one
}

CMD="${1:-help}"; shift || true
case "$CMD" in
    push)     cmd_push ;;
    check)    cmd_check ;;
    apply)    cmd_apply "$@" ;;
    rollback) cmd_rollback ;;
    help|-h|--help|"")
        sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'
        ;;
    *)
        die "알 수 없는 명령: $CMD"
        ;;
esac
