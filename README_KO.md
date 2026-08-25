# botjim (봇짐)

**파일을, 온전히 나르다.** — `tar | netcat`의 감각으로, 속성은 그대로, 끊기면 이어서.

botjim은 리눅스/맥에서 동작하는 CLI 파일 전송 도구입니다. 서버가 대기하고 클라이언트가 push/pull합니다. 모드·소유자·타임스탬프·xattr·심볼릭 링크·하드링크·sparse 홀까지 그대로 옮기고, TCP 한 개 위에서 청크 단위 병렬 전송으로 대용량 파일도 채웁니다. 전송이 중단되면 다시 실행하기만 하면 이어받습니다.

```
$ botjim -s                                    # 서버: 대기하며 btop 스타일 대시보드
$ botjim -c 1.2.3.4 foo*                       # 클라이언트: foo* 를 서버로 push
$ botjim -c 1.2.3.4 --pull 'data/*'            # 서버에서 pull
$ botjim -c 1.2.3.4                            # 경로 없으면 MC 스타일 브라우저로 골라 전송
```

## 기능

- **속성 완전 보존** — mode(setuid/setgid/sticky 포함), uid/gid(`--map-owners`), mtime/atime(나노초), xattr, 심볼릭 링크, 하드링크(데이터 1회 전송), sparse(제로 청크는 전송하지 않음), fifo/디바이스 노드(`--devices`, root). ctime만은 커널이 금지합니다.
- **청크 병렬** — 파일 하나도 4/8/16MiB 청크로 나눠 N개 스트림(`--parallel`, 기본 8)이 동시에 전송. TCP 포트는 하나뿐(yamux 멀티플렉싱).
- **리줌** — 수신측에 `<이름>.fs-part-<nonce>` + 사이드카(청크 해시 비트맵)를 남기고, 재실행 시 재해시로 검증한 청크만 스킵. kill -9 로 100번 죽여도 검증 통과. 이미 완료된 파일은 0바이트 재전송.
- **압축** — 청크 단위 zstd(기본)/lz4/none. 비압축성 데이터는 자동 raw 폴백.
- **TUI** — 서버는 btop 스타일 실시간 대시보드(브라유 스파크라인 처리량, 연결별 진행률, 로그), 클라이언트는 진행률 바·속도·ETA. 파이프에서는 한 줄 폴백.
- **MC 브라우저** — 경로 없이 실행하면 미드나잇 커맨더 스타일 픽커로 space 선택 → 전송. pull은 서버 디렉터리를 원격 탐색.
- **자동 업데이트** — `botjim update` 가 GitHub Releases에서 SHA256SUMS 검증 후 자기 교체.

## 설치

[Releases](https://github.com/ziozzang/botjim/releases)에서 플랫폼용 정적 바이너리를 받아 PATH에 두세요. 또는 소스에서:

```
go build -o botjim ./cmd/botjim
```

## 사용법

```
botjim -s [플래그]                        # 서버 (기본 포트 4761)
botjim -c HOST[:PORT] [PATH...]           # push
botjim -c HOST[:PORT] --pull [RPATH...]   # pull
botjim update [--check|--force]           # 자동 업데이트
```

서버는 `--root`를 감옥(jail)로 삼습니다 — 모든 수신 파일은 그 안에만 들어가고, pull도 그 안에서만 읽습니다. `..`/절대경로/심볼릭 링크를 통한 탈출은 거부합니다.

자주 쓰는 플래그:

| 플래그 | 기본 | 설명 |
|---|---|---|
| `-p/--port` | 4761 | 포트 |
| `--root DIR` | `.` | 서버 루트(감옥) |
| `--dest DIR` | `.` | pull 수신 디렉토리 |
| `--compress` | `zstd` | `zstd` \| `lz4` \| `none` |
| `--parallel` | 8 | 데이터 스트림 수 (1..32) |
| `--resume` | `on` | `on`(size+mtime) \| `size` \| `fresh` |
| `--map-owners` | `none` | `none` \| `numeric` \| `name` (서버 정책) |
| `--devices` | off | fifo/디바이스 노드 포함 |
| `--no-tui` | | 한 줄 진행 표시 |

glob은 셸이 확장한 인자를 그대로 받고, 따옴표로 넘어온 패턴은 직접 확장합니다(`**` 재귀 지원). 파일명에 `*`이 들어간 리터럴 경로는 존재하면 리터럴이 이깁니다.

## 성능 (루프백 tmpfs, 16코어)

| 워크로드 | botjim | `tar \| nc`(압축해제 포함) |
|---|---|---|
| 5GiB 단일 파일 (none, p=8) | **1397 MiB/s** | 1054 MiB/s |
| 5GiB 단일 (zstd-3) | 1159 MiB/s | — |
| 20k × 64KiB 소파일 | 348 MiB/s | 437 MiB/s |
| 1GiB 난수 (zstd, raw 폴백) | 1163 MiB/s | 390 MiB/s |
| 1GiB 제로(sparse) | 0.09초 (구멍은 전송 안 함) | — |

## 프로토콜 개요

TCP 한 개: 36바이트 핸드셰이크(magic `FSY1`, 기능비트, crc32c) → yamux 멀티플렉싱 → 컨트롤 스트림(매니페스트·HaveBitmap·FileResult) + N개 데이터 스트림(청크 프레임). 청크 정체성은 `SHA-256(경로‖인덱스‖데이터)` — 잘못된 위치에 쓰인 온전한 데이터도 검출됩니다. 암호화(V1 평문)는 `transport.CipherFunc` 자리에 X25519+ChaCha20-Poly1305 레코드 레이어를 끼우면 프레임 변경 없이 활성화되도록 설계되어 있습니다.

## 보안 고지

V1은 **평문**입니다. 신뢰하는 네트워크/VPN/ssh 터널에서 쓰세요. 서버는 root 감옥 밖 접근을 거부하지만, 접속 자체는 누구나 할 수 있고(포트가 열려 있으면) 누구나 push할 수 있습니다 — 인증 토큰은 V1.1 계획에 있습니다.

## 개발

```
make test        # 단위 + 통합 (push/pull × 압축 × 병렬 행렬, 리줌)
make race        # -race 2회
make harnesses   # 속성 하니스 + kill -9 스위트 + docker 컨테이너 E2E
make bench       # tar|nc 기준 벤치마크
```

## 라이선스

MIT — [LICENSE](LICENSE)
