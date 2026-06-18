#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# KISA Audit - common utilities (logging, backup, atomic edit, rollback execution)
# Sourced by kisa-audit.sh and handlers. Do not execute directly.
#
# 단일 호스트 자가 완결 실행 모델:
#   - 임시 상태는 mktemp -d 로 만든 KISA_TMP_DIR 에 두고 EXIT trap 으로 자동 삭제
#   - 백업은 원본 옆 <file>.kisa.bak (이미 있으면 skip — 최초 원본 보존)
#   - 원본 없는 파일을 apply 가 새로 만든 경우 <file>.kisa.bak.absent 마커
#   - 임시 파일 자동 정리: 시스템에 영구 디렉터리/로그/심링크 미생성 (런 종료 시 KISA_TMP_DIR 자동 삭제)
#   - report.html 단일 산출물 — kisa-audit.sh 실행 디렉터리에 생성

[[ -n "${_KISA_COMMON_LOADED:-}" ]] && return 0
_KISA_COMMON_LOADED=1

# ---------------- Paths ----------------
# KISA_BASE 는 kisa-audit.sh 가 SCRIPT_DIR 로 export 해서 넘겨준다.
# 단독으로 source 한 경우(예: 테스트)에 한해 이 파일 위치에서 역추적.
if [[ -z "${KISA_BASE:-}" ]]; then
    KISA_BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fi
# Lock 파일은 KISA_BASE 안에 둠 (시스템 영구 디렉터리 미사용).
: "${KISA_LOCK_FILE:=$KISA_BASE/.kisa-audit.lock}"

# 런타임에 kisa-audit.sh 가 init_run 호출 시 설정
KISA_TMP_DIR="${KISA_TMP_DIR:-}"
KISA_MODE="${KISA_MODE:-check}"

# 백업 suffix — 원본과 충돌하지 않는 식별자
: "${KISA_BAK_SUFFIX:=.kisa.bak}"
: "${KISA_BAK_ABSENT_SUFFIX:=.kisa.bak.absent}"
: "${KISA_STATE_DIR:=/var/lib/kisa-audit}"
: "${KISA_ROLLBACK_LOG:=$KISA_STATE_DIR/rollback.jsonl}"

# Python 인터프리터 자동 탐색 (Rocky 8 minimal 은 platform-python 만 있음)
if   command -v python3 >/dev/null 2>&1;       then PYTHON="$(command -v python3)"
elif [[ -x /usr/libexec/platform-python ]];    then PYTHON=/usr/libexec/platform-python
elif command -v python >/dev/null 2>&1;        then PYTHON="$(command -v python)"
else PYTHON=""
fi
export PYTHON

# ---------------- ANSI colors ----------------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
    C_RESET=$(tput sgr0);  C_BOLD=$(tput bold)
    C_RED=$(tput setaf 1); C_GREEN=$(tput setaf 2); C_YELLOW=$(tput setaf 3)
    C_BLUE=$(tput setaf 4); C_MAGENTA=$(tput setaf 5); C_CYAN=$(tput setaf 6); C_GREY=$(tput setaf 8)
else
    C_RESET=; C_BOLD=; C_RED=; C_GREEN=; C_YELLOW=; C_BLUE=; C_MAGENTA=; C_CYAN=; C_GREY=
fi

# ---------------- Logging (콘솔 전용 — 파일 미기록) ----------------
log_info()  { local msg="$*"; [[ "${KISA_QUIET:-0}" == 1 ]] || printf '%b\n' "$msg"; }
log_warn()  { local msg="$*"; printf '%b\n' "${C_YELLOW}$msg${C_RESET}" >&2; }
log_error() { local msg="$*"; printf '%b\n' "${C_RED}$msg${C_RESET}"     >&2; }
log_debug() { local msg="$*"; [[ "${KISA_VERBOSE:-0}" == 1 ]] && printf '%b\n' "${C_GREY}$msg${C_RESET}" || true; }
die()       { log_error "$*"; exit 1; }

# ANSI escape (CSI: ESC [ ... letter, charset designation: ESC ( letter) 제거.
# run_handler 가 핸들러 stdout+stderr 를 같이 캡처할 때 log_warn 의 색상이 사유에 섞여
# report.html 에 노출되는 것 방지.
_strip_ansi() {
    sed -E $'s/\x1b\\[[0-9;]*[A-Za-z]//g; s/\x1b\\([A-Z0-9]//g; s/\x1b\\)[A-Z0-9]//g'
}

# ---------------- JSON helpers ----------------
json_escape() {
    "$PYTHON" -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<< "${1:-}"
}

# ---------------- Preflight ----------------
preflight_check() {
    [[ $EUID -eq 0 ]] || die "root 권한으로 실행해야 합니다. 'sudo $0 ...' 로 재실행하세요."

    if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
        die "bash 4.0 이상이 필요합니다. 현재: ${BASH_VERSION}"
    fi

    local missing=()
    local cmd
    for cmd in systemctl awk sed grep cp install mv find stat getfacl setfacl flock mktemp; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if ((${#missing[@]} > 0)); then
        die "필수 명령 누락: ${missing[*]}"
    fi
    [[ -n "$PYTHON" ]] || die "Python 인터프리터를 찾을 수 없습니다. (python3 또는 /usr/libexec/platform-python 필요)"
}

# ---------------- Lock (flock with stale-PID recovery) ----------------
acquire_lock() {
    # EXIT/INT/TERM 모두에서 cleanup 실행 — SIGTERM 시에도 lock 파일 정리
    trap '_kisa_cleanup' EXIT INT TERM
    exec 9>"$KISA_LOCK_FILE"
    if ! flock -n 9; then
        local stale_pid
        stale_pid=$(cat "$KISA_LOCK_FILE" 2>/dev/null || true)
        # PID 가 비어있거나 (process 죽었음) 프로세스가 살아있지 않으면 stale 로 간주 → 강제 해제
        if [[ -n "$stale_pid" ]] && kill -0 "$stale_pid" 2>/dev/null; then
            die "다른 kisa-audit 인스턴스가 이미 실행 중 (PID=$stale_pid)."
        fi
        log_warn "오래된 lock 감지 (PID=${stale_pid:-empty}). 강제 해제 후 진행."
        # 기존 lock 파일 강제 삭제 후 재획득
        flock -u 9 2>/dev/null || true
        rm -f "$KISA_LOCK_FILE" 2>/dev/null || true
        exec 9>"$KISA_LOCK_FILE"
        flock -w 5 9 || die "lock 획득 실패"
    fi
    printf '%s' "$$" > "$KISA_LOCK_FILE"
}

_kisa_cleanup() {
    flock -u 9 2>/dev/null || true
    rm -f "$KISA_LOCK_FILE" 2>/dev/null || true
    if [[ -n "${KISA_TMP_DIR:-}" && -d "$KISA_TMP_DIR" ]]; then
        rm -rf "$KISA_TMP_DIR" 2>/dev/null || true
    fi
}

# ---------------- Run init (ephemeral tmp dir) ----------------
init_run() {
    KISA_TMP_DIR=$(mktemp -d -t kisa-audit.XXXXXX) || die "mktemp -d 실패"
    chmod 700 "$KISA_TMP_DIR"
    mkdir -p "$KISA_TMP_DIR"/{evidence,backup-log,tmp}
    export KISA_TMP_DIR
}

# ---------------- File backup (in-place .kisa.bak) ----------------
# backup_file <absolute_path>
#   원본 옆에 <path>.kisa.bak 으로 보존. 이미 존재하면 skip (최초 원본 유지).
#   원본이 부재하면 <path>.kisa.bak.absent 마커 (rollback 시 삭제 처리).
#   현재 핸들러가 건드린 경로는 KISA_TMP_DIR/backup-log/<code>.list 에 기록 (per-item 롤백용).
backup_file() {
    local src="$1"
    [[ -z "$src" ]] && return 0
    [[ "$src" = /* ]] || { log_warn "backup_file: 절대경로 아님: $src"; return 1; }

    local bak="${src}${KISA_BAK_SUFFIX}"
    local absent="${src}${KISA_BAK_ABSENT_SUFFIX}"

    # per-handler 백업 로그 — restore 대상 식별
    if [[ -n "${KISA_CURRENT_HANDLER:-}" && -n "${KISA_TMP_DIR:-}" ]]; then
        local blog="$KISA_TMP_DIR/backup-log/${KISA_CURRENT_HANDLER}.list"
        grep -qxF "$src" "$blog" 2>/dev/null || printf '%s\n' "$src" >> "$blog"
    fi

    if [[ ! -e "$src" && ! -L "$src" ]]; then
        # 원본 부재 — apply 가 새로 생성할 경우 rollback 시 삭제할 수 있게 마커만 남김.
        # 이미 .kisa.bak 가 있다면(이전 apply 결과 원본 옆에 백업 보존됨) absent 마커 생성 안 함.
        if [[ ! -e "$bak" && ! -e "$absent" ]]; then
            : > "$absent"
            chmod 600 "$absent" 2>/dev/null || true
        fi
        return 0
    fi

    # 이미 백업 파일이 있다면 — 가장 이른 원본 보존이 원칙이므로 skip
    [[ -e "$bak" ]] && return 0

    # 백업 생성 — 메타데이터/심링크 보존
    cp -a --no-dereference "$src" "$bak"
    log_debug "backed up: $src -> $bak"
}

# ---------------- Per-handler in-run restore ----------------
# restore_file <absolute_path>
#   해당 핸들러가 apply 직후 실패했을 때, 같은 런 안에서 즉시 원복.
#   .kisa.bak 가 있으면 그 내용으로, .kisa.bak.absent 가 있으면 원본 삭제.
restore_file() {
    local src="$1"
    [[ "$src" = /* ]] || { log_warn "restore_file: 절대경로 아님: $src"; return 1; }
    local bak="${src}${KISA_BAK_SUFFIX}"
    local absent="${src}${KISA_BAK_ABSENT_SUFFIX}"

    if [[ -e "$absent" ]]; then
        [[ -e "$src" || -L "$src" ]] && rm -f "$src"
        rm -f "$absent"
        log_debug "restore_file: removed (was ABSENT): $src"
        return 0
    fi
    if [[ -e "$bak" ]]; then
        cp -a --no-dereference "$bak" "$src"
        command -v restorecon >/dev/null 2>&1 && restorecon "$src" 2>/dev/null || true
        log_debug "restore_file: restored from .kisa.bak: $src"
        return 0
    fi
    log_warn "restore_file: 백업/ABSENT 기록 없음 — 복원 건너뜀: $src"
    return 1
}

# ---------------- Atomic file rewrite ----------------
# atomic_write <target_file> <mode:0644> <owner:root> <group:root>
atomic_write() {
    local tgt="$1" mode="${2:-0644}" owner="${3:-root}" group="${4:-root}"
    local tmp="$KISA_TMP_DIR/tmp/atomic.$$.$RANDOM"
    install -m "$mode" -o "$owner" -g "$group" /dev/null "$tmp"
    cat > "$tmp"
    mv -f "$tmp" "$tgt"
    if command -v restorecon >/dev/null 2>&1; then
        restorecon "$tgt" 2>/dev/null || true
    fi
}

# ---------------- Config-line replace-or-append ----------------
# set_kv <file> <key_regex> <new_line>
set_kv() {
    local file="$1" key_re="$2" new_line="$3"
    backup_file "$file"
    [[ -f "$file" ]] || { printf '%s\n' "$new_line" > "$file"; return 0; }

    local orig_mode="" orig_uid="" orig_gid=""
    orig_mode=$(stat -c '%a' "$file" 2>/dev/null || true)
    orig_uid=$(stat -c '%u'  "$file" 2>/dev/null || true)
    orig_gid=$(stat -c '%g'  "$file" 2>/dev/null || true)

    # 활성 라인이 있으면 그 라인 교체.
    # 활성 라인 없고 주석 처리된 #key 라인이 있으면 그 첫 줄을 활성 라인으로 교체.
    # 둘 다 없으면 파일 끝에 새 라인 추가.
    if grep -qE "^[[:space:]]*${key_re}([[:space:]]|=)" "$file"; then
        local tmp; tmp="$KISA_TMP_DIR/tmp/edit.$$.$RANDOM"
        awk -v key_re="$key_re" -v new_line="$new_line" '
            BEGIN{done=0}
            {
              if (!done && match($0, "^[[:space:]]*(" key_re ")([[:space:]]|=)")) {
                print new_line; done=1
              } else {
                print
              }
            }' "$file" > "$tmp"
        mv -f "$tmp" "$file"
    elif grep -qE "^[[:space:]]*#[[:space:]]*${key_re}([[:space:]]|=)" "$file"; then
        # 주석 라인 활성화 + 값 교체 (첫 등장 라인만)
        local tmp; tmp="$KISA_TMP_DIR/tmp/edit.$$.$RANDOM"
        awk -v key_re="$key_re" -v new_line="$new_line" '
            BEGIN{done=0}
            {
              if (!done && match($0, "^[[:space:]]*#[[:space:]]*(" key_re ")([[:space:]]|=)")) {
                print new_line; done=1
              } else {
                print
              }
            }' "$file" > "$tmp"
        mv -f "$tmp" "$file"
    else
        printf '\n%s\n' "$new_line" >> "$file"
    fi

    [[ -n "$orig_mode" ]] && chmod "$orig_mode" "$file" 2>/dev/null || true
    [[ -n "$orig_uid" && -n "$orig_gid" ]] && chown "$orig_uid:$orig_gid" "$file" 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && restorecon "$file" 2>/dev/null || true
}

# ---------------- Per-handler rollback plan queue ----------------
# 핸들러가 apply 중 호출 — service reload, semanage 등 파일 외 조작 기록
# 두 곳에 기록:
#   1) per-handler 휘발 파일 (_KISA_RB_PLAN_FILE) — items.jsonl rollback_plan 용
#   2) 영구 파일 (KISA_ROLLBACK_LOG) — rollback_run() 에서 실제 실행 대상
_queue_rollback() {
    local op="$1" args="${2:-}"
    local code="${KISA_CURRENT_HANDLER:-_unknown}"
    local rec
    rec=$("$PYTHON" -c 'import json,sys,time; print(json.dumps({"ts":time.strftime("%Y-%m-%dT%H:%M:%S"),"code":sys.argv[1],"op":sys.argv[2],"args":sys.argv[3]}))' "$code" "$op" "$args")
    # 1) 휘발 (items.jsonl rollback_plan 용)
    local f="${_KISA_RB_PLAN_FILE:-}"
    if [[ -n "$f" ]]; then
        printf '%s\n' "$rec" >> "$f"
    fi
    # 2) 영구 — rollback_run() 이 실제로 재생할 큐
    #    중복 적재 방지: 같은 (code, op, args) 가 이미 있으면 skip.
    if [[ "${KISA_MODE:-}" == "apply" ]]; then
        mkdir -p "$KISA_STATE_DIR" 2>/dev/null
        chmod 700 "$KISA_STATE_DIR" 2>/dev/null
        local key
        key=$("$PYTHON" -c 'import json,sys; o=json.loads(sys.argv[1]); print(json.dumps({"code":o["code"],"op":o["op"],"args":o["args"]}, sort_keys=True))' "$rec" 2>/dev/null)
        local already=0
        if [[ -s "$KISA_ROLLBACK_LOG" && -n "$key" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                local existing
                existing=$("$PYTHON" -c 'import json,sys; o=json.loads(sys.argv[1]); print(json.dumps({"code":o.get("code",""),"op":o.get("op",""),"args":o.get("args","")}, sort_keys=True))' "$line" 2>/dev/null)
                if [[ "$existing" == "$key" ]]; then
                    already=1; break
                fi
            done < "$KISA_ROLLBACK_LOG"
        fi
        if (( already == 0 )); then
            printf '%s\n' "$rec" >> "$KISA_ROLLBACK_LOG"
            chmod 600 "$KISA_ROLLBACK_LOG" 2>/dev/null
        fi
    fi
}

# ---------------- Service operation (apply 종료 직후 즉시 실행) ----------------
# 단일 호스트 로컬 실행 모델에서는 SSH 세션 절단 우려가 없으므로 즉시 호출.
# 같은 런 안에서 동일 (op,svc) 중복 호출은 1회로 deduplicate.
_KISA_SERVICE_OPS_DONE=""
_run_service_op() {
    local op="$1" svc="$2"
    [[ -z "$op" || -z "$svc" ]] && return 0
    local key="${op}:${svc}"
    case " $_KISA_SERVICE_OPS_DONE " in *" $key "*) return 0 ;; esac
    _KISA_SERVICE_OPS_DONE="$_KISA_SERVICE_OPS_DONE $key"
    if systemctl "$op" "$svc" >/dev/null 2>&1; then
        log_debug "systemctl $op $svc OK"
        return 0
    fi
    if [[ "$op" == "reload" ]]; then
        if systemctl restart "$svc" >/dev/null 2>&1; then
            log_debug "reload 실패 → restart 로 대체 OK: $svc"
            return 0
        fi
    fi
    log_warn "systemctl $op $svc 실패"
    return 1
}

# 호환 alias — 기존 핸들러는 _queue_service_op 를 호출. 즉시 실행 모델로 매핑.
_queue_service_op() {
    _run_service_op "$1" "$2"
}

# systemctl is-enabled 의 안전 wrapper. 일부 상태(disabled/static)에서 stdout 출력
# 후 exit=1 을 반환하므로 `cmd || printf` 패턴이 두 출력을 합쳐 버린다.
# 이 함수는 stdout 의 첫 줄만 캡처하고, 빈 결과는 fallback 값으로 채운다.
#
# 사용:  cur_state=$(_safe_unit_state vsftpd)
#        cur_state=$(_safe_unit_state telnet.socket "disabled")  # fallback 명시
_safe_unit_state() {
    local unit="$1"
    local fallback="${2:-disabled}"
    local out
    out="$(systemctl is-enabled "$unit" 2>/dev/null)"
    out="${out%%$'\n'*}"   # 첫 줄만
    [[ -z "$out" ]] && out="$fallback"
    printf '%s' "$out"
}

# ---------------- Record item result (TMP_DIR 의 items.jsonl) ----------------
record_item() {
    # args: code title severity category before action after detail evidence_json error rollback_json [meta_extra_json]
    local code="$1" title="$2" sev="$3" cat="$4" before="$5" action="$6" after="$7"
    local detail="$8" evidence="${9:-null}" err="${10:-null}" rb="${11:-[]}" meta_extra="${12:-{\}}"
    # 병렬 점검 시 핸들러별 파일(KISA_ITEMS_FILE)에 기록 → 나중에 코드 순서로 병합 (동시 append 경합 방지).
    local file="${KISA_ITEMS_FILE:-$KISA_TMP_DIR/items.jsonl}"
    "$PYTHON" - "$code" "$title" "$sev" "$cat" "$before" "$action" "$after" "$detail" "$evidence" "$err" "$rb" "$meta_extra" "$file" <<'PY'
import json, sys
code,title,sev,cat,before,action,after,detail,evidence,err,rb,meta_extra,file=sys.argv[1:14]
def loadmaybe(s,default):
    if s is None or s=='' or s=='null': return default
    try: return json.loads(s)
    except Exception: return default
rec = {
  "code": code, "title": title, "severity": sev, "category": cat,
  "before": before, "action": action, "after": after,
  "detail": detail,
  "evidence": loadmaybe(evidence, None),
  "error": loadmaybe(err, None),
  "rollback_plan": loadmaybe(rb, []),
}
me = loadmaybe(meta_extra, {})
if isinstance(me, dict):
    for k, v in me.items():
        if k in rec: continue
        rec[k] = v
with open(file,'a',encoding='utf-8') as f:
    f.write(json.dumps(rec, ensure_ascii=False)+"\n")
PY
}

# ---------------- Evidence capture (TMP_DIR 휘발) ----------------
_evidence_capture() {
    local label="${1:-evidence}"
    local code="${KISA_CURRENT_HANDLER:-_unknown}"
    local dir="$KISA_TMP_DIR/evidence/$code"
    mkdir -p "$dir"
    cat >> "$dir/$label.txt"
}

# 점검 대상 파일/디렉터리의 메타데이터 + 텍스트 파일이면 내용까지 dump
_dump_path() {
    local p="$1"
    local pattern="${2:-}"
    if [[ ! -e "$p" && ! -L "$p" ]]; then
        echo "(없음) $p"
        return 0
    fi
    ls -ld "$p" 2>&1
    [[ -f "$p" && -r "$p" ]] || return 0
    [[ -z "$pattern" ]] && return 0

    case "$p" in
        /proc/*|/sys/*)
            local content; content=$(head -c 4096 "$p" 2>/dev/null)
            [[ -z "$content" ]] && { echo "    [empty]"; return 0; }
            printf '%s\n' "$content" | grep -nE "$pattern" | sed 's/^/    /' || echo "    (매칭 없음)"
            return 0
            ;;
    esac
    local sz; sz=$(stat -c%s "$p" 2>/dev/null || echo 0)
    if (( sz == 0 )); then echo "    [empty]"; return 0; fi
    if command -v file >/dev/null 2>&1; then
        local enc; enc=$(file -b --mime-encoding "$p" 2>/dev/null)
        [[ "$enc" == "binary" ]] && { echo "    [bin]"; return 0; }
    fi
    local hits; hits=$(grep -nE "$pattern" "$p" 2>/dev/null | head -50)
    if [[ -n "$hits" ]]; then
        printf '%s\n' "$hits" | sed 's/^/    /'
    else
        echo "    (매칭 라인 없음)"
    fi
}

_evidence_to_json() {
    local code="$1"
    local dir="$KISA_TMP_DIR/evidence/$code"
    [[ -d "$dir" ]] || { echo 'null'; return 0; }
    "$PYTHON" - "$dir" <<'PY'
import json, os, sys
d = sys.argv[1]
out = {}
for fn in sorted(os.listdir(d)):
    if not fn.endswith('.txt'): continue
    label = fn[:-4]
    with open(os.path.join(d, fn), encoding='utf-8', errors='replace') as f:
        out[label] = f.read()
print(json.dumps(out, ensure_ascii=False) if out else 'null')
PY
}

# ---------------- 핸들러 출력 캡처 ----------------
# 핸들러의 stdout(= printf verdict) 만 "결과 사유"(detail) 로 캡처한다.
# stderr(log_warn/log_error 진단·항목별 안내) 는 detail 에 섞지 않고 콘솔로 흘려보낸다.
# → 결과 사유가 한 줄 verdict 로 깔끔해지고, 상세 목록은 evidence 영역이 담당.
_kisa_run_capture() {   # usage: out=$(_kisa_run_capture fn [args...]); rc=$?
    # 숨김(.) 이름 금지 — U-33(숨김파일 점검)이 이 임시파일을 오탐하지 않도록.
    # $BASHPID(서브셸 고유 PID) 사용 — 병렬 점검 시 핸들러간 파일 충돌 방지($$ 는 메인 PID 라 공유됨).
    local _ef="${KISA_TMP_DIR:-/tmp}/hstderr.$BASHPID"
    "$@" 2>"$_ef"
    local _rc=$?
    if [[ -s "$_ef" ]]; then cat "$_ef" >&2; fi
    rm -f "$_ef"
    return $_rc
}

# 파일시스템 점검(SUID/SGID·world-writable 등) 시 제외할 비-호스트 경로.
# 컨테이너 이미지 레이어·systemd factory 템플릿·스냅/플랫팩 번들은 호스트의
# 실행 벡터가 아니며(호스트 $PATH 아님, 호스트 사용자가 직접 exec 안 함),
# 오히려 chmod -s 등 "조치" 시 이미지/패키지 원본을 변조(rpm -V·이미지 무결성 깨짐)하므로
# 점검 대상에서 제외한다. (CIS 등 표준 점검도 호스트 FS 만 스캔)
_kisa_excluded_roots() {
    cat <<'EOF'
/usr/share/factory
/var/lib/containers
/var/lib/docker
/var/lib/flatpak
/var/lib/lxc
/var/lib/lxd
/snap
EOF
}

# find 의 -prune 절(\( ... \) -prune) 에 넣을 -path 배열을 NAMEREF 로 채운다.
# 사용:  local -a _pr=(); _kisa_build_prune_expr _pr   # → ( -path A -o -path B ... )
_kisa_build_prune_expr() {
    local -n _out="$1"
    _out=()
    local p
    while IFS= read -r p; do
        [[ -n "$p" ]] && _out+=( -path "$p" -o )
    done < <(_kisa_excluded_roots)
    [[ -n "${KISA_BASE:-}" ]] && _out+=( -path "$KISA_BASE" -o )
    # 마지막 -o 제거
    (( ${#_out[@]} )) && unset '_out[${#_out[@]}-1]'
}

# ---------------- 병렬 점검 디스패처 (check 전용) ----------------
# check 는 읽기 전용이라 병렬 실행해도 안전하다. 각 핸들러를 동시 실행 수 제한 하에
# 백그라운드로 돌리고, 결과(items)·콘솔출력을 핸들러별 파일에 모은 뒤 코드 순서로
# 한꺼번에 병합·출력한다.
#   - items 경합: KISA_ITEMS_FILE 로 핸들러별 파일 분리 후 순서대로 cat.
#   - evidence/hstderr: 각각 code·$BASHPID 로 분리되어 충돌 없음.
# ⚠️ apply 는 시스템 변경(/etc·PAM·systemctl) 경합과 롤백 순서 안전을 위해 병렬 금지 — 순차 실행만.
run_handlers_parallel() {
    local codes=("$@")
    local maxjobs; maxjobs=$(nproc 2>/dev/null || echo 4)
    [[ "$maxjobs" =~ ^[0-9]+$ ]] || maxjobs=4
    (( maxjobs < 1 )) && maxjobs=1
    (( maxjobs > 8 )) && maxjobs=8

    local idir="$KISA_TMP_DIR/items.d" cdir="$KISA_TMP_DIR/console.d"
    mkdir -p "$idir" "$cdir"
    log_info "  병렬 점검 중 … (항목 ${#codes[@]}개 · 최대 ${maxjobs} 동시 실행)"

    local code running=0
    for code in "${codes[@]}"; do
        (
            trap - ERR                                   # 백그라운드 핸들러 실패가 전역 _on_err(render_report) 를 부르지 않도록
            export KISA_ITEMS_FILE="$idir/${code}.jsonl"
            run_handler "$code" || true
        ) >"$cdir/${code}.out" 2>&1 &
        running=$((running+1))
        if (( running >= maxjobs )); then
            wait -n 2>/dev/null || wait
            running=$((running-1))
        fi
    done
    wait

    # 결과 병합 (코드 순서 유지) — render_report 가 읽는 items.jsonl 생성
    : > "$KISA_TMP_DIR/items.jsonl"
    for code in "${codes[@]}"; do
        [[ -s "$idir/${code}.jsonl" ]] && cat "$idir/${code}.jsonl" >> "$KISA_TMP_DIR/items.jsonl"
    done
    # 콘솔 결과 일괄 출력 (코드 순서) — "결과값 한번에"
    for code in "${codes[@]}"; do
        [[ -f "$cdir/${code}.out" ]] && cat "$cdir/${code}.out"
    done
}

# ---------------- Run handler in subshell isolation ----------------
run_handler() {
    local code="$1"
    local fn_prefix="h_${code//-/_}"
    local handler="$KISA_BASE/lib/handlers/${code}.sh"

    if [[ ! -f "$handler" ]]; then
        log_warn "handler 없음: $code (skipped)"
        record_item "$code" "(missing)" "-" "-" "-" "not_applicable" "-" "handler 파일 없음" null null '[]'
        return 0
    fi

    # shellcheck disable=SC1090
    (
      set +eE
      trap - ERR
      source "$handler"
      export KISA_CURRENT_HANDLER="$code"
      local meta title sev cat
      meta=$("${fn_prefix}_meta" 2>/dev/null || echo '{}')
      readarray -t _parsed < <(printf '%s' "$meta" | "$PYTHON" -c '
import sys, json
try:
    d = json.loads(sys.stdin.read() or "{}")
except Exception:
    d = {}
print(d.get("title",""))
print(d.get("severity",""))
print(d.get("category",""))
' 2>/dev/null)
      title="${_parsed[0]:-}"
      sev="${_parsed[1]:-}"
      cat="${_parsed[2]:-}"

      local before_output before_rc before
      export KISA_PHASE
      if [[ "$KISA_MODE" == "check" ]]; then KISA_PHASE="current"; else KISA_PHASE="before"; fi
      before_output=$(_kisa_run_capture "${fn_prefix}_check") || before_rc=$?
      before_rc="${before_rc:-0}"
      before_output=$(printf '%s' "$before_output" | _strip_ansi)
      case $before_rc in
        0) before=양호 ;;
        1) before=취약 ;;
        3) before=해당없음 ;;
        *) before=판정불가 ;;
      esac

      if [[ "$KISA_MODE" == "check" ]]; then
          local ev_json; ev_json=$(_evidence_to_json "$code")
          local check_action="checked"
          [[ "$before" == "해당없음" ]] && check_action="not_applicable"
          # audit.conf 가 있을 때만 _apply --dry-run 호출하여 "조치 후 예상" 미리보기.
          # 없으면 정책값 미정의 → 조치 미리보기 비활성, AFTER = BEFORE 유지.
          local check_detail="$before_output"
          local expected_after="$before"
          if [[ "$before" == "취약" || "$before" == "판정불가" ]] && [[ "${_AUDIT_CONF_LOADED:-0}" == "1" ]]; then
              local plan_output plan_rc
              plan_output=$(_kisa_run_capture "${fn_prefix}_apply" --dry-run) || plan_rc=$?
              plan_rc="${plan_rc:-0}"
              plan_output=$(printf '%s' "$plan_output" | _strip_ansi)
              # 핸들러 dry-run 메시지의 표준 접두어를 사전 제거 (콘솔 라벨과 중복 방지).
              # _print_line 의 ' (' cut 룰이 발동해 detail 이 잘리는 것 방지.
              local _plan_clean="${plan_output#(dry-run) }"
              _plan_clean="${_plan_clean#\[MANUAL\] }"
              _plan_clean="${_plan_clean#\[FAIL\] }"
              [[ -n "$_plan_clean" ]] && check_detail="$_plan_clean"
              # 자동 조치 보류 케이스 분류:
              #   - "미설정"/"미지정" 키워드 → audit.conf 정책값 비어있음. 값 채우면 자동 조치 됨.
              #   - 그 외 manual → 시스템 상태가 직접 조작 필요 (chown/rm 등 OS 명령).
              if [[ "$plan_output" =~ 미설정 ]] || [[ "$plan_output" =~ 미지정 ]]; then
                  expected_after="$before"
                  check_detail="[정책 미설정] $check_detail"
              elif [[ "$plan_rc" == "2" ]] || [[ "$plan_output" =~ 수동 ]] || [[ "$plan_output" =~ \[MANUAL\] ]] || [[ "$plan_output" =~ manual ]]; then
                  expected_after="$before"
                  check_detail="[수동 조치] $check_detail"
              elif [[ "$plan_rc" == "3" ]]; then
                  expected_after="해당없음"
              else
                  expected_after="양호"
              fi
          fi
          record_item "$code" "$title" "$sev" "$cat" "$before" "$check_action" "$expected_after" "$check_detail" "$ev_json" null '[]' "$meta"
          _print_line "$code" "$title" "$sev" "$before" "$check_action" "$expected_after" "$check_detail"
          return 0
      fi

      # apply mode
      if [[ "$before" == "양호" ]]; then
          local skip_detail="${before_output:-이미 양호}"
          local ev_json; ev_json=$(_evidence_to_json "$code")
          record_item "$code" "$title" "$sev" "$cat" "$before" "skipped" "$before" "$skip_detail" "$ev_json" null '[]' "$meta"
          _print_line "$code" "$title" "$sev" "$before" "skipped" "$before" "$skip_detail"
          return 0
      fi
      if [[ "$before" == "해당없음" ]]; then
          local na_detail="${before_output:-해당사항 없음}"
          local ev_json; ev_json=$(_evidence_to_json "$code")
          record_item "$code" "$title" "$sev" "$cat" "$before" "not_applicable" "$before" "$na_detail" "$ev_json" null '[]' "$meta"
          _print_line "$code" "$title" "$sev" "$before" "not_applicable" "$before" "$na_detail"
          return 0
      fi

      local apply_output apply_rc action after_output after_rc after

      local _KISA_RB_PLAN_FILE="$KISA_TMP_DIR/tmp/rb.${code}.$$"
      : > "$_KISA_RB_PLAN_FILE"
      export _KISA_RB_PLAN_FILE

      KISA_PHASE="apply"
      apply_output=$(_kisa_run_capture "${fn_prefix}_apply") || apply_rc=$?
      apply_rc="${apply_rc:-0}"
      apply_output=$(printf '%s' "$apply_output" | _strip_ansi)
      case "$apply_rc" in
        0) action=applied ;;
        2) action=manual  ;;
        3) action=not_applicable ;;
        *) action=failed  ;;
      esac

      KISA_PHASE="after"
      after_output=$(_kisa_run_capture "${fn_prefix}_check") || after_rc=$?
      after_rc="${after_rc:-0}"
      after_output=$(printf '%s' "$after_output" | _strip_ansi)
      case "$after_rc" in
        0) after=양호 ;;
        1) after=취약 ;;
        *) after=판정불가 ;;
      esac

      if [[ "$action" == "failed" ]]; then
          log_warn "$code 조치 실패. 해당 항목만 롤백 시도."
          rollback_item_in_run "$code" || log_error "$code 자동 롤백 중 오류"
          "${fn_prefix}_check" >/dev/null 2>&1 && after=양호 || after=취약
          : > "$_KISA_RB_PLAN_FILE"
      fi

      local rb_json='[]'
      if [[ -s "$_KISA_RB_PLAN_FILE" ]]; then
          rb_json=$("$PYTHON" - "$_KISA_RB_PLAN_FILE" <<'PY'
import json, sys
ops=[]
with open(sys.argv[1], encoding='utf-8') as f:
    for ln in f:
        ln=ln.strip()
        if not ln: continue
        try: ops.append(json.loads(ln))
        except Exception: pass
print(json.dumps(ops, ensure_ascii=False))
PY
)
      fi

      local ev_json; ev_json=$(_evidence_to_json "$code")
      record_item "$code" "$title" "$sev" "$cat" "$before" "$action" "$after" "$apply_output" "$ev_json" null "$rb_json" "$meta"
      _print_line "$code" "$title" "$sev" "$before" "$action" "$after" "$apply_output"
    )
}

# Print one line to stdout
_print_line() {
    local code="$1" title="$2" sev="$3" before="$4" action="$5" after="$6" detail="$7"
    local color_before color_after color_action
    case "$before" in 양호) color_before="$C_GREEN" ;; 취약) color_before="$C_YELLOW" ;; *) color_before="$C_GREY" ;; esac
    case "$after"  in 양호) color_after="$C_GREEN"  ;; 취약) color_after="$C_RED"    ;; *) color_after="$C_GREY" ;; esac
    case "$action" in
        applied)  color_action="$C_GREEN"  ;;
        skipped)  color_action="$C_GREY"   ;;
        manual)   color_action="$C_YELLOW" ;;
        failed)   color_action="${C_BOLD}${C_RED}" ;;
        checked)  color_action="$C_CYAN"   ;;
        not_applicable) color_action="$C_GREY" ;;
        *)        color_action="$C_GREY"   ;;
    esac
    local sev_color
    case "$sev" in 상) sev_color="$C_RED" ;; 중) sev_color="$C_YELLOW" ;; 하) sev_color="$C_GREY" ;; *) sev_color="$C_GREY" ;; esac
    # 콘솔 detail 표시 정책:
    #   - applied/skipped/not_applicable: detail 숨김 (결과만 표시)
    #   - manual/failed: 사유 짧게 노출
    #   - checked + 취약/판정불가: "조치 계획" 짧게 노출 (사용자가 조치 후 변화 미리 볼 수 있게)
    #   - checked + 양호: detail 숨김 (중복 표시 방지)
    # 전체 사유는 항상 report.html 에 보존.
    local short_detail=""
    local _show_detail=0
    case "$action" in
        manual|failed) _show_detail=1 ;;
        checked)
            [[ "$before" == "취약" || "$before" == "판정불가" ]] && _show_detail=1
            ;;
    esac
    if (( _show_detail )); then
        short_detail="${detail%%$'\n'*}"
        # action 칸과 중복되는 접두어 제거
        short_detail="${short_detail#(dry-run) }"
        short_detail="${short_detail#\[MANUAL\] }"
        short_detail="${short_detail#\[FAIL\] }"
        # 부가 설명(괄호·대괄호·세미콜론·em-dash) 이전까지만 잘라 핵심 한 마디만 노출.
        # 전체 사유는 report.html 에 보존됨.
        short_detail="${short_detail%% (*}"
        short_detail="${short_detail%% \[*}"
        short_detail="${short_detail%%;*}"
        short_detail="${short_detail%% — *}"
        local _max="${KISA_DETAIL_WIDTH:-80}"
        ((${#short_detail} > _max)) && short_detail="${short_detail:0:_max-3}..."
    fi
    # check / apply 동일 형식: BEFORE >> action >> AFTER.
    # check 모드에서 AFTER 는 "조치 시 예상 결과" (run_handler 가 dry-run 결과 분류).
    # apply 모드에서 AFTER 는 실제 조치 후 결과.
    local title_pad; title_pad=$(_pad_visual "$title" 50)
    # after 색상: "수동" 추가 처리 (yellow)
    case "$after" in 양호) color_after="$C_GREEN" ;; 취약) color_after="$C_RED" ;; 수동) color_after="$C_YELLOW" ;; *) color_after="$C_GREY" ;; esac
    if [[ -n "$short_detail" ]]; then
        printf '%b%-6s%b %s %b[%s]%b  %bBEFORE:%-7s%b  %b>> %-10s >>%b  %bAFTER:%-7s%b  %s\n' \
            "$C_BOLD" "$code" "$C_RESET" \
            "$title_pad" \
            "$sev_color" "$sev" "$C_RESET" \
            "$color_before" "$before" "$C_RESET" \
            "$color_action" "$action" "$C_RESET" \
            "$color_after" "$after" "$C_RESET" \
            "${C_GREY}${short_detail}${C_RESET}"
    else
        printf '%b%-6s%b %s %b[%s]%b  %bBEFORE:%-7s%b  %b>> %-10s >>%b  %bAFTER:%-7s%b\n' \
            "$C_BOLD" "$code" "$C_RESET" \
            "$title_pad" \
            "$sev_color" "$sev" "$C_RESET" \
            "$color_before" "$before" "$C_RESET" \
            "$color_action" "$action" "$C_RESET" \
            "$color_after" "$after" "$C_RESET"
    fi
}
_truncate() {
    local s="$1" max="$2"
    if ((${#s} > max)); then printf '%s...' "${s:0:max-3}"; else printf '%-*s' "$max" "$s"; fi
}
# 한글/CJK 폭 고려 padding — East Asian Width 정확 계산 (curly quote 등 1칸 char 보정).
# bash 로는 정확히 못 재서 python unicodedata 사용. 항목당 1회 호출.
_pad_visual() {
    "$PYTHON" -c '
import sys, unicodedata
s = sys.argv[1]; m = int(sys.argv[2])
w = sum(2 if unicodedata.east_asian_width(c) in ("W","F") else 1 for c in s)
if w >= m: sys.stdout.write(s + " ")
else: sys.stdout.write(s + " " * (m - w))
' "$1" "$2"
}

# ---------------- Per-item in-run rollback (apply 실패 자동 복구) ----------------
rollback_item_in_run() {
    local code="$1"
    local blog="$KISA_TMP_DIR/backup-log/${code}.list"
    if [[ ! -s "$blog" ]]; then
        log_debug "per-item rollback: $code (백업 로그 없음 — 복원할 파일 없음)"
        return 0
    fi
    local restored=0 failed=0 p
    set +e
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        if restore_file "$p" 2>/dev/null; then
            restored=$((restored + 1))
        else
            failed=$((failed + 1))
            log_warn "per-item rollback: 복원 실패 — $p"
        fi
    done < "$blog"
    set -e
    log_info "$code per-item rollback: 복원 $restored 개, 실패 $failed 개"
    (( failed == 0 ))
}

# ---------------- Full rollback (시스템 전수 .kisa.bak 스캔) ----------------
# 시스템 영역에서 *.kisa.bak / *.kisa.bak.absent 파일을 찾아 원복.
#   *.kisa.bak           → 원본 경로로 복원
#   *.kisa.bak.absent    → 원본 경로 파일 삭제 (apply 가 새로 만든 것)
# 원복 후 백업 자체는 삭제 (다시 apply 하면 새 백업 생성).
rollback_run() {
    log_info "${C_CYAN}[롤백] 큐된 액션 재생 + 시스템 전수 *.kisa.bak 스캔${C_RESET}"

    local _state_queue _delayed_userdel_queue
    _state_queue="$(mktemp)"
    _delayed_userdel_queue="$(mktemp)"

    # ─── Phase 1: 영구 큐 액션 재생 (LIFO) ───
    # apply 시 _queue_rollback 으로 적재된 액션 실행.
    # 예: userdel <ADMIN_USER>, authselect disable-feature with-faillock 등.
    # 파일/서비스 복원 전에 먼저 실행 → 사용자 추가/잠금 위험 액션 처리.
    local rb_actions=0 rb_failed=0
    if [[ -s "$KISA_ROLLBACK_LOG" ]]; then
        log_info "  영구 rollback 큐: $KISA_ROLLBACK_LOG"
        # 2단계 처리:
        #   Pass A — non-state ops (exec/restart/reload/setenforce/semanage_port_del/grubby_*)
        #            : LIFO 순서. 파일 복원·서비스 재시작 등을 먼저 처리.
        #   Pass B — systemctl_state ops (LAST)
        #            : enable/disable/mask 같은 최종 상태는 가장 마지막에 적용.
        #            예) U-53 이 systemctl_restart vsftpd 큐, U-54 가 systemctl_state vsftpd:disabled 큐
        #            → Pass A 에서 restart 가 vsftpd 살리면 Pass B 의 disable 가 마무리해서
        #              최종 상태 = disabled. 같은 서비스에 대한 restart 가 disable 를 무력화 못 함.

        local _action_runner
        _action_runner() {
            local op="$1" args="$2"
            local rc=0
            case "$op" in
                exec)
                    bash -c "$args" >/dev/null 2>&1 || rc=$?
                    ;;
                systemctl_reload)
                    systemctl reload "$args" >/dev/null 2>&1 \
                        || systemctl restart "$args" >/dev/null 2>&1 \
                        || rc=$?
                    ;;
                systemctl_restart)
                    systemctl restart "$args" >/dev/null 2>&1 || rc=$?
                    ;;
                systemctl_state)
                    local _svc="${args%%:*}" _state="${args#*:}"
                    if [[ -n "$_svc" && "$_svc" != "$args" ]]; then
                        case "$_state" in
                            enabled|active)
                                systemctl unmask "$_svc" >/dev/null 2>&1
                                systemctl enable --now "$_svc" >/dev/null 2>&1 || rc=$?
                                ;;
                            disabled|inactive)
                                systemctl disable --now "$_svc" >/dev/null 2>&1 || rc=$?
                                ;;
                            masked)
                                systemctl mask "$_svc" >/dev/null 2>&1 || rc=$?
                                ;;
                            *) rc=99 ;;
                        esac
                    else
                        systemctl $args >/dev/null 2>&1 || rc=$?
                    fi
                    ;;
                setenforce)
                    if [[ "$args" =~ ^(0|1|Permissive|Enforcing)$ ]]; then
                        setenforce "$args" >/dev/null 2>&1 || rc=$?
                    else
                        rc=99
                    fi
                    ;;
                semanage_port_del)
                    if command -v semanage >/dev/null 2>&1; then
                        # shellcheck disable=SC2086
                        semanage port -d $args >/dev/null 2>&1 || rc=$?
                    fi
                    ;;
                grubby_add_args)
                    if command -v grubby >/dev/null 2>&1; then
                        grubby --update-kernel=ALL --args="$args" >/dev/null 2>&1 || rc=$?
                    fi
                    ;;
                grubby_remove_args)
                    if command -v grubby >/dev/null 2>&1; then
                        grubby --update-kernel=ALL --remove-args="$args" >/dev/null 2>&1 || rc=$?
                    fi
                    ;;
                *)
                    log_warn "알 수 없는 rollback op: $op (args=$args)"
                    rc=98
                    ;;
            esac
            return $rc
        }

        local op args line rc
        set +e
        # ── Pass A: non-state ops ──
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            op=$("$PYTHON" -c 'import json,sys; print(json.loads(sys.argv[1]).get("op",""))' "$line" 2>/dev/null)
            args=$("$PYTHON" -c 'import json,sys; print(json.loads(sys.argv[1]).get("args",""))' "$line" 2>/dev/null)
            [[ -z "$op" ]] && continue
            if [[ "$op" == "systemctl_state" ]]; then
                printf '%s\n' "$line" >> "$_state_queue"
                continue
            fi
            if [[ "$args" == *"userdel"* ]]; then
                printf '%s\n' "$line" >> "$_delayed_userdel_queue"
                log_info "  지연 롤백 대상 감지 (사용자 삭제 지연): $args"
                continue
            fi
            rc=0
            _action_runner "$op" "$args" || rc=$?
            if (( rc == 0 )); then
                rb_actions=$((rb_actions + 1))
                log_debug "rb $op OK: $args"
            else
                rb_failed=$((rb_failed + 1))
                log_warn "rb $op 실패 (rc=$rc): $args"
            fi
        done < <(tac "$KISA_ROLLBACK_LOG" 2>/dev/null)
        # ── Pass B: systemctl_state (마지막) ──
        if [[ -s "$_state_queue" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                op=$("$PYTHON" -c 'import json,sys; print(json.loads(sys.argv[1]).get("op",""))' "$line" 2>/dev/null)
                args=$("$PYTHON" -c 'import json,sys; print(json.loads(sys.argv[1]).get("args",""))' "$line" 2>/dev/null)
                [[ -z "$op" ]] && continue
                rc=0
                _action_runner "$op" "$args" || rc=$?
                if (( rc == 0 )); then
                    rb_actions=$((rb_actions + 1))
                    log_debug "rb $op OK: $args"
                else
                    rb_failed=$((rb_failed + 1))
                    log_warn "rb $op 실패 (rc=$rc): $args"
                fi
            done < "$_state_queue"
        fi
        rm -f "$_state_queue"
        unset -f _action_runner
        set -e
        # 큐 비우기 (파일 자체는 남기고 truncate)
        : > "$KISA_ROLLBACK_LOG" 2>/dev/null
    fi
    log_info "  큐 액션 재생 완료 — 성공 ${rb_actions}개, 실패 ${rb_failed}개"

    # ─── Phase 2: 시스템 전수 *.kisa.bak 스캔 ───

    # 핸들러들이 backup_file 을 호출할 수 있는 모든 영역을 포함.
    # 확인된 영역: /etc (대부분), /usr/bin (U-37 crontab), /var/log (U-67), /usr/lib/systemd (U-17).
    # 표기 경로가 부재해도 find 가 무시하므로 안전.
    local scan_paths=(
        /etc
        /root
        /home
        /var/log
        /var/spool
        /var/lib
        /usr/local
        /usr/bin
        /usr/sbin
        /usr/lib/systemd
        /sbin
        /bin
        /opt
        /boot
    )
    # KISA_BASE(스크립트 자기 자신) 트리는 제외
    local restored=0 absent_removed=0 failed=0

    # set -e 환경에서 (( var++ )) 가 rc=1 을 반환해 함수 중단되는 문제 회피
    set +e
    local f orig
    while IFS= read -r -d '' f; do
        case "$f" in "$KISA_BASE"/*) continue ;; esac
        orig="${f%${KISA_BAK_SUFFIX}}"
        if cp -a --no-dereference "$f" "$orig" 2>/dev/null; then
            command -v restorecon >/dev/null 2>&1 && restorecon "$orig" 2>/dev/null
            rm -f "$f" 2>/dev/null
            restored=$((restored + 1))
            log_debug "restored: $orig"
        else
            failed=$((failed + 1))
            log_warn "복원 실패: $orig"
        fi
    done < <(find "${scan_paths[@]}" -xdev -type f -name "*${KISA_BAK_SUFFIX}" -print0 2>/dev/null)

    while IFS= read -r -d '' f; do
        case "$f" in "$KISA_BASE"/*) continue ;; esac
        orig="${f%${KISA_BAK_ABSENT_SUFFIX}}"
        if [[ -e "$orig" || -L "$orig" ]]; then
            if rm -f "$orig" 2>/dev/null; then
                absent_removed=$((absent_removed + 1))
            else
                failed=$((failed + 1))
            fi
        fi
        rm -f "$f" 2>/dev/null
        log_debug "removed (was ABSENT): $orig"
    done < <(find "${scan_paths[@]}" -xdev -type f -name "*${KISA_BAK_ABSENT_SUFFIX}" -print0 2>/dev/null)
    set -e

    log_info "${C_GREEN}[롤백] 완료${C_RESET} — 큐액션 ${rb_actions}개, 복원 ${restored}개, 부재마커 삭제 ${absent_removed}개, 실패 $((failed + rb_failed))개"

    # ─── Phase 3: rollback 후 PAM faillock 잔존 lock 해제 ───
    # apply 가 faillock 활성 + lock-out 까지 만들면 conf 파일 복원만으로는 lock 해제 안 됨.
    # KISA 적용 후 rollback 시 안전하게 모든 사용자 faillock 초기화.
    if command -v faillock >/dev/null 2>&1; then
        faillock --reset >/dev/null 2>&1 || true
        log_info "  faillock --reset 실행 (잔존 lock 해제)"
    fi

    # ─── Phase 4: SSH 서비스 restart (sshd_config 복원 반영) ───
    # 포트 변경 등 모든 설정을 확실히 적용하기 위해 restart 수행.
    # established 세션이 끊길 수 있으나 trap '' HUP 으로 남은 백그라운드 작업은 완료됨.
    if systemctl is-active sshd >/dev/null 2>&1; then
        if systemctl restart sshd >/dev/null 2>&1; then
            log_info "  sshd restart (복원된 sshd_config 및 포트 적용)"
        else
            log_warn "  sshd restart 실패 — sshd_config 수동 검증 필요"
        fi
    fi

    # ─── Phase 5: firewalld reload (복원된 zone XML 을 runtime 에 반영) ───
    # Phase 1 에서 큐 액션이 reload 했지만 그 시점에는 zone XML 이 아직 KISA 상태.
    # Phase 2 가 zone XML 을 vendor 로 복원했으므로 다시 reload 필요.
    # --no-flush: conntrack table 보존 → 기존 established TCP(특히 SSH) 세션 끊김 방지.
    # 룰 자체는 즉시 새 permanent 로 교체되며, 새 SYN 만 새 룰로 평가됨.
    if systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --reload --no-flush >/dev/null 2>&1 || true
        log_info "  firewalld --reload --no-flush (복원된 zone XML 적용, conntrack 보존)"
    fi

    # ─── Phase 6: 지연된 userdel 액션 비동기 실행 ───
    # admin 자기 자신을 지울 때 SSH 세션이 pkill 로 터지는 현상 방지.
    if [[ -s "$_delayed_userdel_queue" ]]; then
        log_info "  지연된 사용자 삭제 백그라운드 비동기 구동..."
        local _del_line _del_op _del_args
        while IFS= read -r _del_line; do
            [[ -z "$_del_line" ]] && continue
            _del_op=$("$PYTHON" -c 'import json,sys; print(json.loads(sys.argv[1]).get("op",""))' "$_del_line" 2>/dev/null)
            _del_args=$("$PYTHON" -c 'import json,sys; print(json.loads(sys.argv[1]).get("args",""))' "$_del_line" 2>/dev/null)
            [[ -z "$_del_op" ]] && continue
            
            # setsid 와 sleep 을 이용해 3초 뒤 백그라운드에서 실행하도록 위임.
            # 이 스크립트가 성공 반환(exit 0)하고 SSH 세션이 완전히 끊긴 후에 백그라운드에서 계정이 삭제됨.
            nohup sh -c "sleep 3; $_del_args" >/dev/null 2>&1 &
        done < "$_delayed_userdel_queue"
    fi
    rm -f "$_state_queue" "$_delayed_userdel_queue"

    (( failed + rb_failed == 0 ))
}
