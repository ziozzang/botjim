# botjim (봇짐)

> 이 문서는 한국어 판입니다 — 기준 문서는 [README.md](README.md)(영어)와 [ARCHITECTURE.md](ARCHITECTURE.md)입니다.

**파일을, 온전히 나르다.** — `tar | netcat`의 감각으로. 속성은 그대로, 청크 병렬, 끊기면 이어받기, 그리고 서로 직접 닿을 수 없는 머신끼리는 **종단간 암호화 릴레이**로.

botjim은 리눅스/맥에서 동작하는 CLI 파일 전송 도구입니다. 서버가 대기하고 클라이언트가 push/pull합니다. 모드·소유자·타임스탬프·xattr·심볼릭 링크·하드링크·sparse 홀까지 그대로 옮기고, TCP 한 개 위에서 청크 단위 병렬 전송으로 대용량 파일도 채웁니다. 전송이 중단되면 다시 실행하기만 하면 이어받습니다.

```
$ botjim server                                # 서버: 대기하며 btop 스타일 대시보드
$ botjim send 1.2.3.4 foo*                     # foo* 를 서버로 push
$ botjim pull 1.2.3.4 'data/*'                 # 서버에서 pull
$ botjim send 1.2.3.4                          # 경로 없으면 MC 스타일 브라우저

$ botjim relay                                 # 릴레이 브로커 (페어링 + 스풀)
$ botjim send --via relay.example.com data/    # 릴레이로 push (코드 출력)
$ botjim recv --via relay.example.com --code 코드   # 반대편에서 수신
```

## 기능

- **속성 완전 보존** — mode(setuid/setgid/sticky 포함), uid/gid(`--map-owners`), mtime/atime(나노초), xattr, 심볼릭 링크, 하드링크(데이터 1회 전송), sparse(제로 청크는 전송하지 않음), fifo/디바이스 노드(`--devices`, root). ctime만은 커널이 금지합니다.
- **청크 병렬** — 파일 하나도 4/8/16MiB 청크로 나눠 N개 스트림(`--parallel`, 기본 8)이 동시에 전송. TCP 포트는 하나뿐(yamux 멀티플렉싱).
- **리줌** — 수신측에 `<이름>.fs-part-<nonce>` + 사이드카(청크 해시 비트맵)를 남기고, 재실행 시 재해시로 검증한 청크만 스킵. kill -9 스위트로 검증. 이미 완료된 파일은 0바이트 재전송.
- **압축** — 청크 단위 zstd(기본)/lz4/none. 비압축성 데이터는 자동 raw 폴백.
- **릴레이 모드** — NAT 뒤의 머신끼리: 양쪽 모두 브로커로 아웃바운드 접속, 125비트 코드로 페어링, X25519 + ChaCha20-Poly1305 종단간 암호화 — **브로커는 암호문만 다룹니다**. `--spool-max`(기본 2GiB, 메모리 우선→디스크 스플)까지 버퍼링해 빠른 송신자가 느린 수신자를 앞질러도 됩니다.
- **TUI** — 서버는 btop 스타일 실시간 대시보드(브라유 스파크라인, 연결별·파일별 속도/남은시간). 클라이언트는 진행률 바·실시간 속도·전체/파일별 남은 시간·스크롤 전송 로그. 모든 화면에서 `?` 도움말. 파이프에서는 한 줄 폴백.
- **MC 브라우저** — 경로 없이 실행하면 미드나잇 커맨더 스타일 픽커. space로 파일·**폴더**(하위 전체) 모두 선택, `/` 정규식 필터(매치 하이라이트), PgUp/PgDn 스크롤. pull은 서버 디렉터리를 원격 탐색.
- **자동 업데이트** — `botjim update` 가 GitHub Releases에서 SHA256SUMS 검증 후 자기 교체.

## 설치

[Releases](https://github.com/ziozzang/botjim/releases)에서 플랫폼용 정적 바이너리를 받아 PATH에 두세요. 또는 소스에서:

```
go build -o botjim ./cmd/botjim
```

## 명령

각 명령은 `--help`로 전체 옵션을 봅니다. (구버전의 `-s` / `-c`도 별칭으로 동작합니다.)

| 명령 | 용도 |
|---|---|
| `botjim server [플래그]` | 대기 (기본 포트 4761); `--root`가 감옥 |
| `botjim send HOST[:port] [PATH...]` | push; 경로 없으면 픽커 |
| `botjim pull HOST[:port] [RPATH...]` | `--dest`로 pull |
| `botjim relay [플래그]` | 페어링 브로커 (기본 포트 4762) |
| `botjim send --via RELAY PATH...` | 릴레이로 push; 일회용 페어링 코드 출력 |
| `botjim recv --via RELAY --code CODE` | 릴레이 push를 `--dest`에 수신 |
| `botjim update [--check\|--force]` | 자동 업데이트 |

서버는 `--root`를 감옥으로 삼습니다 — 수신 파일은 그 안에만, pull도 그 안에서만 읽으며 `..`/절대경로/심볼릭 링크 탈출은 거부합니다.

## 릴레이 사용 예

```
머신 C (공개)     $ botjim relay --spool-max 2G

머신 A (NAT 뒤)   $ botjim send --via C.example.com photos/
                 code:  4CSQG-2622A-NA9ZR-PQBMF-1ZT28
                 (이 코드를 B에게 다른 경로로 전달 — 메신저, 전화 등)

머신 B (NAT 뒤)   $ botjim recv --via C.example.com \
                         --code 4CSQG-2622A-NA9ZR-PQBMF-1ZT28
```

릴레이는 `SHA-256(코드)`로만 페어링하며 코드 자체를 모릅니다. 페어링 후 모든 바이트 — botjim 프로토콜 핸드셰이크 포함 — 는 AEAD 레코드 레이어 안을 지납니다. 코드는 일회용(첫 taker가 획득)이며 `--wait`분 후 만료. 위협 모델은 [ARCHITECTURE.md](ARCHITECTURE.md#relay-mode) 참고.

## 성능 (루프백 tmpfs, 16코어)

| 워크로드 | botjim | `tar \| nc`(압축해제 포함) |
|---|---|---|
| 5GiB 단일 파일 (none, p=8) | **1397 MiB/s** | 1054 MiB/s |
| 5GiB 단일 (zstd-3) | 1159 MiB/s | — |
| 20k × 64KiB 소파일 | 348 MiB/s | 437 MiB/s |
| 1GiB 난수 (zstd, raw 폴백) | 1163 MiB/s | 390 MiB/s |
| 1GiB 제로(sparse) | 0.09초 (구멍은 전송 안 함) | — |

## 보안

다이렉트 모드(server/send/pull)는 **평문**입니다 — 신뢰하는 네트워크/VPN/ssh 터널에서 쓰세요. 릴레이 모드는 구조적으로 종단간 암호화됩니다: 브로커는 암호문만 갖고, 복호화할 수 없고, 변조는 탐지됩니다. 악의적 릴레이가 할 수 있는 일은 서비스 거부와 시점·크기 관찰뿐입니다.

## 개발

```
make test        # 단위 + 통합 (push/pull × 압축 × 병렬 행렬, 리줌, 감옥, 릴레이)
make race        # -race
make harnesses   # 속성 하니스 + kill -9 스위트 + docker 컨테이너 E2E
make bench       # tar|nc 기준 벤치마크
```

## 라이선스

MIT — [LICENSE](LICENSE)
