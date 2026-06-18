# Handler 작성 규격 (U-XX.sh 공통)

## 파일 위치·명명

- 경로: `lib/handlers/U-XX.sh` (프로젝트 루트 기준 — XX = 2자리, 예: U-02.sh, U-13.sh, U-67.sh)
- 함수명: 하이픈을 언더스코어로 치환 — U-05 → `h_U_05_meta / _check / _apply`
- shebang + 파일 상단 주석으로 항목명·중요도·판단 기준 요약·OS별 차이점·조치 전략·롤백 전략 기재.

## 반드시 정의할 3개 함수

```bash
h_U_XX_meta() {
    cat <<'JSON'
{"code":"U-XX","title":"<한글 항목명>","severity":"상|중|하","category":"<카테고리명>"}
JSON
}

h_U_XX_check() {
    # stdout: 한 줄 사유 (짧게), return code:
    #   0 = 양호   1 = 취약   2 = 판정불가   3 = 해당없음(OS 미대상)
    :
}

h_U_XX_apply() {
    # 첫 인자 "--dry-run" 이면 실제 변경 없이 계획만 출력하고 return 0.
    # return 0 = applied, 1 = failed, 2 = manual(수동 조치 필요), 3 = not_applicable.
    :
}
```

- check/apply 둘 다 stdout 는 사람에게 보여줄 짧은 한 줄(리포트 detail 필드). `printf` 사용, 개행 금지.
- apply 는 변경 성공 후 재실행해도 안전해야 함(idempotent).

## 공통 API (lib/common.sh 에서 제공)

### 1. 파일 백업·원복
- `backup_file <abs-path>` — 원본 옆에 `<abs-path>.kisa.bak` 으로 복사 (mode/uid/gid/SELinux 컨텍스트 보존, 심링크 그대로). 같은 파일에 대해 idempotent — 이미 `.kisa.bak` 있으면 skip(최초 원본 보존). 파일이 부재하면 `<abs-path>.kisa.bak.absent` 마커 생성 → rollback 시 apply 가 새로 만든 파일을 삭제.
- `restore_file <abs-path>` — 같은 run 안에서만 사용. backup_file 이후 즉시 원복. 검증 실패·부분 오류 시 사용.
- 백업은 변경 직전 **반드시** 호출. set_kv/atomic_write 은 자동 backup_file 하지만, 당신이 수동 편집하기 전에도 직접 호출 권장.

### 2. 설정 라인 수정
- `set_kv <file> <key_regex> <new_line>`
  - 첫 번째로 나오는 `^[space:]*<key_regex>([space:]|=)` 라인을 `<new_line>` 로 치환. 없으면 `new_line` 을 끝에 append.
  - 파일 mode/uid/gid + SELinux context 자동 복원. key_regex 는 BRE 아니고 ERE.
  - 예: `set_kv /etc/login.defs 'PASS_MAX_DAYS' 'PASS_MAX_DAYS\t90'`

### 3. 원자적 파일 교체
- `atomic_write <tgt> [mode=0644] [owner=root] [group=root]`
  - stdin → tmp → mv. mode/owner/group 지정·SELinux restorecon 자동.

### 4. 서비스 재시작 지연 큐 (중요)
- `_queue_service_op <op> <svc>` (op: reload|restart)
  - 핸들러가 직접 `systemctl reload sshd` 호출 금지. 관리자 세션을 끊을 위험 있는 서비스(sshd, firewalld, network 계열 등)는 반드시 이 큐에 enqueue.
  - `kisa-audit.sh` 가 전 핸들러 종료·리포트 렌더링 후 `_flush_service_queue()` 로 일괄 실행.
  - 재검증(`after`)은 데몬 상태가 아니라 config 파일 기반(`sshd -t`, `visudo -cf`, etc.)으로 판정.

### 5. 롤백 플랜 큐잉
- `_queue_rollback <op> <args>` — rollback 시 파일 원복 이후 실행할 시스템 연산 등록.
  - 지원 op: `systemctl_reload <svc>` / `systemctl_restart <svc>` / `systemctl_state <svc>:<enabled|disabled|masked>` / `semanage_port_del <proto <port>>` / `sysctl <key=value>`
  - 예: apply 에서 `_queue_service_op reload sshd` 를 했다면 반드시 `_queue_rollback systemctl_reload sshd` 도 같이 등록.

### 6. 로깅·판단
- `log_info/warn/error/debug` — 사용자 출력(quiet/verbose 자동 처리). handler 에서 남발 금지.
- `die <msg>` — 치명 오류. handler 안에서는 거의 사용 X (`return 1` 선호).

## 환경변수 (kisa-audit.sh 가 export 함 — 참고)

| 변수 | 의미 | 기본값 |
|------|------|--------|
| `OS_FAMILY` | rocky8 / rocky9 / rocky10 | 필수 |
| `OS_PRETTY` | `/etc/os-release` PRETTY_NAME | |
| `OS_MAJOR` | 8/9/10 | |
| `PKG_MGR` | dnf / yum | |
| `AUTHSELECT_AVAILABLE` | 0/1 | Rocky 8+ 거의 1 |
| `KISA_BASE` | 스크립트 트리 루트 | kisa-audit.sh 가 SCRIPT_DIR 로 export |
| `KISA_TMP_DIR` | mktemp -d 결과 (런 종료 시 자동 삭제) | evidence/, backup-log/, tmp/ 하위 |
| `KISA_INVOCATION_DIR` | 호출 디렉터리 (report.html 생성 위치) | |
| `KISA_DRY_RUN` | 0/1 | |
| `PYTHON` | python3 절대경로 | |
| `SSH_PERMIT_ROOT_LOGIN` | no (U-01) | |
| `PASSWORD_MIN_LEN / MAX_AGE / MIN_AGE / WARN_AGE` | 8 / 90 / 1 / 7 | U-02 |
| `LOGIN_MAX_RETRY / LOGIN_LOCK_TIME` | 5 / 120 | U-03 |
| `SESSION_TIMEOUT` | 600 | U-12 |
| `UMASK_VALUE` | 022 | U-30 |
| `ALLOWED_HOSTS` | 빈 문자열 | U-28 — **비어있으면 apply 금지, manual 로** |
| `NFS_ALLOWED_NETWORKS` | 빈 | U-39/40 |
| `SNMP_COMMUNITY_ENV_VAR` | KISA_SNMP_COMMUNITY | U-60 — env var 로 값 전달 |
| `SNMP_ALLOWED_NETWORKS` | 빈 | U-61 |
| `DNS_ZONE_ALLOW_TRANSFER` | none | U-50 |
| `LOGIN_BANNER_TEXT` | (기본 문자열, kisa-audit.sh 내 하드코딩) | U-62 |
| `NTP_SERVERS` | kr.pool.ntp.org,time.bora.net | U-65 |
| `SUDOERS_ADMIN_GROUP` | wheel | U-63 |
| `FTP_MODE / TELNET_MODE / AUTO_UPDATE` | disable / disable / none | |

추가 변수 필요 시 `kisa-audit.sh` 의 `# ---------- defaults ----------` 블록에 기본값 선언 + `export` 목록에 추가.

## Rocky 8/9/10 호환 규칙

1. **Rocky 8 ≠ Rocky 9/10**: sshd_config drop-in (`Include` 지시자) 은 Rocky 9/10 에서만 기본 활성. PAM 구조도 차이 있음.
2. **PAM 관리 도구**:
   - Rocky 8+ 공식: `authselect`. 커스텀 프로파일 생성 후 `authselect select custom/<name>` 로 활성.
   - `/etc/pam.d/system-auth`, `/etc/pam.d/password-auth` 는 symlink 이거나 authselect 가 관리. 직접 편집하면 authselect 상태와 불일치.
   - 본 프로젝트 방침: authselect 프로파일에 "include" 되는 drop-in(예: `system-auth-local`) 생성하지 말고, **`/etc/security/pwquality.conf.d/`** 같은 애플리케이션 drop-in 이 있는 항목은 drop-in 우선. 없으면 system-auth 에 직접 set_kv (대신 authselect 프로파일을 벗어나지 않음).
3. **systemd 차이**: `systemctl mask` / `disable --now` 는 모든 OS 동일 동작. `systemctl is-enabled` 반환값은 동일.
4. **FTP/Telnet 패키지**: Rocky 9/10 기본 저장소에 `telnet-server`, `vsftpd` 있음. 미설치 시 U-34/52/54 는 해당없음(return 3).
5. **SNMP 패키지**: `net-snmp`. Rocky 8/9/10 공통.
6. **DNS**: `bind` 패키지. named.conf 경로 동일.
7. **NFS**: Rocky 9/10 은 `nfs-server.service`, Rocky 8 도 동일.
8. **메일**: 기본적으로 `postfix` (3대 동일).

## 코드 스타일

- `set -Eeuo pipefail` 는 `kisa-audit.sh` 에서 설정. handler 는 subshell 안에서 `set +eE` 로 실행되므로 `return` 값 반환이 에러 트랩 안 걸림. 즉 취약 판정은 `return 1` 로 편하게.
- 명령어 체크: `command -v <cmd> >/dev/null 2>&1` 후 사용.
- 하드코딩 금지: 경로·기본값은 위 환경변수로. 파일 경로는 handler 상단 private 함수 `_uXX_<name>_path()` 로 래핑.
- 임시 파일: `$KISA_TMP_DIR/tmp/<prefix>.$$.$RANDOM` — cross-fs `mv` 후 반드시 mode/uid/gid/SELinux 복원.
- `printf` 우선(echo 는 escape 처리 불일치). heredoc 쓸 때 `<<'JSON'` 처럼 인용으로 변수 확장 차단.

## 자동조치 불가 항목의 처리

- 사용자 계정 정리(U-07), UID=0 계정 수동검토(U-05), SUID 파일 전수 조치(U-23) 등은 자동 조치 시 시스템 운영에 영향. 이런 항목은:
  1. `check` 는 취약 판정 후 사유 상세 출력.
  2. `apply` 는 `return 2` (manual) + stdout 에 관리자가 해야 할 단계 안내.

## 예시: U-01.sh (이 파일과 같은 디렉터리) 를 반드시 정독하고 스타일 모방.

## 최종 검증 원칙

- apply 성공 후 _check 가 다시 실행되어 before 취약 → after 양호 이어야 함 (kisa-audit.sh 가 자동 재검증).
- 파일 수정 후 서비스 config-level 검증 있으면 반드시 실행: sshd -t, visudo -cf, named-checkconf, chronyd -q(금지), `rsyslogd -N1`, `postfix check`.
- 검증 실패 시 `restore_file` 로 즉시 원복.
