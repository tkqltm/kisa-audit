# KISA Audit — Handler 작성 규약

## 파일 위치
`lib/handlers/U-XX.sh` (예: `U-02.sh`) — 프로젝트 루트 기준 상대 경로.

## 파일 구조 (필수 3함수)

```bash
#!/usr/bin/env bash
# U-XX: <제목> (중요도: 상/중/하)
# KISA 가이드 요약 / OS 차이 / 조치 전략을 서두 주석으로

h_U_XX_meta() {
    cat <<'JSON'
{"code":"U-XX","title":"<제목>","severity":"상|중|하","category":"<카테고리>"}
JSON
}

h_U_XX_check() {
    # return 0=양호 1=취약 2=판정불가
    # printf 로 사유를 stdout 에 1줄 출력 (items.jsonl 의 detail 로 기록됨)
}

h_U_XX_apply() {
    # 첫 인자 "--dry-run" 이면 변경 예정만 출력 후 return 0
    # return 0=성공 1=실패(파일 원복 필수) 2=수동 조치 필요 3=해당없음
}
```

handler 함수는 `h_U_01_check` 처럼 `-` 가 `_` 로 변환된 이름을 써야 한다 (run_handler 가 `h_${code//-/_}` 로 조합).

## 사용 가능한 common 유틸 (`lib/common.sh`)

### 로깅
- `log_info "msg"` — 일반 정보 (KISA_QUIET=1 이면 숨김)
- `log_warn "msg"` — 경고 (stderr, 노란색)
- `log_error "msg"` — 에러 (stderr, 빨간색)
- `log_debug "msg"` — 디버그 (KISA_VERBOSE=1 에서만)

### 파일 백업/복원 (rollback 자동 지원)
- `backup_file /abs/path` — 현재 run-dir 에 백업 + mode/uid/gid/ACL 기록. 파일이 없으면 ABSENT 마커만 기록 (rollback 시 해당 파일 삭제됨). 같은 파일에 대해 idempotent.
- `restore_file /abs/path` — 해당 run 내에서 임시로 복원 (handler 내부 실패 시 사용). rollback 서브커맨드용 아님.

### 설정 파일 편집
- `set_kv <file> <key_regex> <new_line>` — 첫 번째 비주석 매치 라인을 new_line 으로 교체, 없으면 append. 자동으로 backup_file 호출, mode/uid/gid/SELinux 컨텍스트 보존.
  - 예: `set_kv /etc/login.defs "PASS_MAX_DAYS" "PASS_MAX_DAYS 90"`
- `atomic_write <target> <mode:0644> <owner:root> <group:root>` — stdin 에서 읽어서 tmp 에 쓰고 mv. SELinux 컨텍스트 자동 restorecon. `set_kv` 로 불가능한 경우(신규 파일·전체 덮어쓰기) 사용.

### 서비스 조작 (중요: systemctl 직접 호출 금지)
- `_queue_service_op reload  <service>` — apply 중 호출. 모든 handler 와 리포트가 끝난 **뒤** 에 `systemctl reload` 실행. reload 미지원 데몬은 restart 로 fallback. **SSH 세션을 즉시 끊지 않도록 이 큐를 반드시 사용할 것.**
- `_queue_service_op restart <service>` — 재시작이 필수인 경우만.
- `_queue_rollback <op> <args>` — rollback 서브커맨드 실행 시 수행할 보조 작업 등록. op 종류:
  - `systemctl_reload <svc>` / `systemctl_restart <svc>`
  - `systemctl_state  <svc>:<enabled|disabled|masked>` — 롤백 시 이 상태로 되돌림
  - `semanage_port_del tcp <port>` — SELinux 포트 허용 원복
  - `sysctl <key=value>` — 원래 sysctl 값 복원

### 환경
- `$KISA_BASE` — 스크립트 트리 루트 (`lib/`, `config/`, `tools/` 위치)
- `$KISA_TMP_DIR` — 현재 run 의 임시 디렉터리 (`mktemp -d`, EXIT trap 으로 자동 삭제). evidence/, backup-log/, tmp/ 하위 구조
- `$KISA_TMP_DIR/tmp/` — 임시 파일 안전 위치
- `$KISA_INVOCATION_DIR` — 사용자가 `./kisa-audit.sh` 를 호출한 위치 (`report.html` 생성 경로)
- `$PYTHON` — python3 또는 /usr/libexec/platform-python (Rocky 8 minimal 대응)
- `$OS_FAMILY` — rocky8 | rocky9 | rocky10
- `$OS_PRETTY` — "Rocky Linux 9.7 (Blue Onyx)" 등
- 사용자 설정 변수 (kisa-audit.sh 에서 export): PASSWORD_MIN_LEN, PASSWORD_MAX_AGE, LOGIN_MAX_RETRY, LOGIN_LOCK_TIME, SESSION_TIMEOUT, UMASK_VALUE, SSH_PERMIT_ROOT_LOGIN, ALLOWED_HOSTS, DENY_HOSTS, NFS_ALLOWED_NETWORKS, SNMP_ALLOWED_NETWORKS, SNMP_COMMUNITY_ENV_VAR, DNS_ZONE_ALLOW_TRANSFER, LOGIN_BANNER_TEXT, NTP_SERVERS, SUDOERS_ADMIN_GROUP, FTP_MODE, TELNET_MODE, AUTO_UPDATE.

## 설계 원칙

1. **근거 없이 추측 금지**. KISA "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드" 의 해당 항목 판단 기준을 그대로 검증할 것.
2. **Rocky 8/9/10 호환**. 가능한 경우 OS_FAMILY 로 분기. 미지원 OS 는 return 3 (해당없음) + 사유 메시지.
3. **SSH/네트워크 즉시 끊김 방지**. 모든 서비스 reload/restart 는 `_queue_service_op` 로.
4. **backup_file 은 수정 전에 반드시 호출**. 그래야 rollback 이 원복 가능.
5. **검증 후 반영**. 설정 변경 후 `systemctl status`/`sshd -t`/`visudo -cf` 등 파일-레벨 validator 로 문법 검증. 실패하면 `restore_file` 로 전부 원복 후 return 1.
6. **Idempotent**. apply 를 반복 실행해도 부작용 없어야 함. check 가 양호면 apply 는 "skipped" 로 처리됨 (이건 run_handler 가 알아서 함).
7. **에러 메시지 한국어**. 사용자 친화적으로.
8. **하드코딩 금지**. path/port/user 는 변수화 또는 audit.conf 에서 override 가능하게.

## 참고: U-01 (완성본)

`lib/handlers/U-01.sh` 를 모범 예시로 참고. 특히:
- `_u01_has_include()` 로 OS 차이(Rocky 8 는 Include 없음) 분기
- drop-in override 전략 (Rocky 9/10)
- `sshd -t` 로 파일 검증 → 실패 시 `restore_file` 로 전부 원복
- `_queue_service_op reload sshd` 로 지연 reload
- `_queue_rollback systemctl_reload sshd` 로 rollback 시도 자동 재적용

## 테스트
- 다수 호스트 일괄: 프로젝트 루트에서 `./deploy.sh check` (또는 apply/rollback). `targets.conf` 에 등록된 서버에 자동 push → 실행 → `./reports/<timestamp>-<mode>/<host>/report.html` 회수
- 단일 호스트(원격 직접): `tar` 만들어 scp 후 `./kisa-audit.sh check --only U-XX --yes` 형태로 실행. 산출물은 실행 디렉터리의 `report.html`
- 단일 호스트(로컬): `cd /sky/kisa/kisa-audit && ./kisa-audit.sh check --only U-XX --yes`
- 롤백: `./kisa-audit.sh rollback` (시스템 전수 `*.kisa.bak` 스캔 후 원복)
- 3대 IP: `192.168.200.101` (Rocky 8), `192.168.200.102` (Rocky 9), `192.168.200.103` (Rocky 10)
