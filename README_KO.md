# botjim (봇짐)

> 이 문서는 한국어 판입니다 — 기준 문서는 [README.md](README.md)(영어)와 [ARCHITECTURE.md](ARCHITECTURE.md)입니다.

**파일을, 온전히 나르다.** — `tar | netcat`의 감각으로. 속성은 그대로, 청크 병렬, 끊기면 이어받기, 델타 업데이트, 토큰/패스프레이즈/클로크 경화, 종단간 암호화 릴레이, 그리고 대용량 불변 아티팩트용 토큰 조인 스웜까지.

botjim은 리눅스/맥에서 동작하는 CLI 파일 전송 도구입니다. 서버가 대기하고 클라이언트가 push/pull합니다. 모드·소유자·타임스탬프·xattr·심볼릭 링크·하드링크·sparse 홀까지 그대로 옮기고, TCP 한 개 위에서 청크 단위 병렬 전송으로 대용량 파일도 채우며, 중단되면 다시 실행만 하면 이어받고, 바뀐 청크만 다시 보냅니다. 서로 직접 닿을 수 없는 머신끼리는 릴레이가 중계합니다 — 그래도 릴레이는 한 바이트도 읽지 못합니다.

```
$ botjim server --token s3cret                # 서버: 대기하며 btop 스타일 대시보드
$ botjim send 1.2.3.4 foo*                    # foo* 를 서버로 push
$ botjim pull 1.2.3.4 'data/*'                # 서버에서 pull
$ botjim send 1.2.3.4                         # 경로 없으면 MC 스타일 브라우저

$ botjim sync push lab                        # 원샷 미러 (정책은 config에서)
$ tar c dir | botjim pipe send --stdin d.tgz 1.2.3.4   # tar | nc 대체

$ botjim relay                                # 릴레이 브로커 (페어링 + 스풀)
$ botjim send --via relay.example.com data/   # 릴레이로 push (코드 출력)
$ botjim recv --via relay.example.com --code 코드      # 반대편에서 수신
```

## 기능

- **속성 완전 보존** — mode(setuid/setgid/sticky 포함), uid/gid(`--map-owners`), mtime/atime(나노초), xattr, 심볼릭 링크, 하드링크(데이터 1회 전송), sparse(제로 청크는 전송하지 않음), fifo/디바이스 노드(`--devices`, root). ctime만은 커널이 금지합니다.
- **청크 병렬** — 파일 하나도 4/8/16MiB 청크로 나눠 N개 스트림(`--parallel`, 기본 8)이 동시에 전송. TCP 포트는 하나뿐(yamux 멀티플렉싱).
- **리줌** — 수신측에 `<이름>.fs-part-<nonce>` + 사이드카(청크 해시 비트맵)를 남기고, 재실행 시 재해시로 검증한 청크만 스킵. kill -9 스위트로 검증. 이미 완료된 파일은 0바이트 재전송. `--retries`로 전송 중 자동 재접속(지수 백오프, 이전 진행에서 이어서).
- **델타 업데이트** — 파일이 바뀌어도 청크 단위로 재전송: 수신측이 보유 청크를 주장하면(무신뢰 — 송신자가 자기 바이트로 재검증) 다른 청크만 전송. 채택 파일은 커밋 전 전량 해시 검증.
- **압축** — 청크 단위 zstd(기본)/lz4/none. 비압축성 데이터는 자동 raw 폴백.
- **다이렉트 모드 인증·암호화** — `--token`(HMAC 증명, 상수시간 비교), `--pass`(X25519 + ChaCha20-Poly1305 레코드 레이어 — 핸드셰이크까지 전부 암호문), `--cloak PATH`(전체 세션이 WebSocket 업그레이드를 타고 HTTP처럼 보임; 일반 GET엔 디코이 페이지). 셋 다 없으면 다이렉트 모드는 평문 — 신뢰하는 네트워크에서만.
- **릴레이 모드** — NAT 뒤의 머신끼리: 양쪽 모두 브로커로 아웃바운드 접속, 125비트 코드로 페어링, 종단간 암호화 — **브로커는 암호문만 다룹니다**. `--spool-max`(기본 2GiB, 메모리 우선→디스크 스플)까지 버퍼링.
- **스웜 모드** — 토큰 조인 청크 분배(LLM 모델, 데이터셋 등 불변 아티팩트): `swarm seed`가 트리를 해시해 스펙(`.swarm.json`, 파일별 SHA-256 + v2 청크별 SHA 카탈로그, ed25519 서명 선택)으로 만들고 청크 서빙+트래커 announce; `swarm join`은 모든 소스(시드, 검증 완료 조이너, `--http` 정적 호스팅 Range)에서 조립 — rarest-first, 이어받기 가능. 청크는 도착 즉시 카탈로그로 검증되며, 해시가 틀린 바이트를 준 피어는 그 세션에서 차단됩니다. 토큰이 트래커 룸과 피어 링크 암호 키를 겸합니다.
- **필터·속도 제한** — `--exclude`/`--include` 글롭(홀로 쓴 이름은 모든 컴포넌트에 매치, `**` 재귀), `--limit 100M` 대역폭 상한, `--dry-run` 전송 없이 계획만, `--delete` 미러 모드(매니페스트에 없는 목적측 항목 제거, 감옥 범위 내).
- **네임드 엔드포인트·싱크** — `~/.botjim/config.json`에 엔드포인트(`{"lab1": {"addr": "10.0.0.5:4761", "token": "…"}}`)와 타깃별 autosync 정책(include/exclude/delete/dest) 저장; `botjim sync push lab1` / `sync pull lab1`이 그 정책으로 미러링. `send lab1`처럼 이름만 써도 해석됩니다. `sync push --watch`는 소스가 바뀌면(디바운스 후) 계속 미러링 — 재전송은 델타라 저렴합니다.
- **메시 config 전파** — 한 노드에서 엔드포인트 목록을 고치면 전 노드가 수렴: `botjim config publish`가 목록을 ed25519 서명 + 버전 매긴 봉투(`.botjim-mesh.json`)로 싸고, 메시 키를 고정(pin)한 수신 서버가 서명과 단조 증가 버전을 검증한 뒤 자기 config에 자동 병합합니다. 새 프로토콜 없이 일반 sync push로 전달됩니다.
- **파이프 모드** — `tar c x | botjim pipe send --stdin x.tgz HOST`, `botjim pipe cat HOST PATH > file`: 익숙한 파이프인데 엔진 기반(스풀→검증→리줌).
- **감사·영수증** — `--audit`은 모든 전송을 변조 방지 해시체인 저널에 기록(`botjim audit verify|tail`); `--receipt`는 매니페스트 다이제스트가 담긴 JSON 영수증을 남깁니다.
- **TUI** — 서버는 btop 스타일 실시간 대시보드(브라유 스파크라인, 연결별·파일별 속도/남은시간). 클라이언트는 진행률 바·실시간 속도·전체/파일별 남은 시간·스크롤 전송 로그. 모든 화면에서 `?` 도움말. 파이프에서는 한 줄 폴백.
- **MC 브라우저** — 경로 없이 실행하면 미드나잇 커맨더 스타일 픽커. space로 파일·**폴더**(하위 전체) 모두 선택, `/` 정규식 필터(매치 하이라이트), PgUp/PgDn 스크롤. pull은 서버 디렉터리를 원격 탐색.
- **LAN 발견** — `botjim server --discover`가 멀티캐스트로 비컨(옵트인); `botjim peers`로 네트워크의 서버를 이름/주소/버전/루트와 함께 표시.
- **HTTP 브리지·메트릭** — `botjim serve [DIR]`: Range 지원 일반 HTTP — 브라우저/curl/HF 스타일 다운로더가 로컬 트리를 그대로 소비. `botjim server --metrics :9090`은 Prometheus 카운터(세션·파일·바이트·에러·활성)를 노출합니다.
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
| `botjim server [플래그]` | 대기 (기본 포트 4761); `--root`가 감옥; `--discover`로 LAN 비컨 |
| `botjim send HOST\|NAME [PATH...]` | push; 경로 없으면 픽커; NAME은 config 엔드포인트 해석 |
| `botjim pull HOST\|NAME [RPATH...]` | `--dest`로 pull |
| `botjim sync push\|pull NAME` | 타깃 autosync 정책으로 원샷 미러; `push --watch`로 상시 미러링 |
| `botjim config publish` | 엔드포인트를 메시 봉투로 서명(자동 전파용) |
| `botjim pipe send --stdin NAME HOST` | stdin → 원격 파일 (`tar \| nc` 대체) |
| `botjim pipe cat HOST PATH` | 원격 파일 → stdout |
| `botjim peers` | LAN의 `--discover` 서버 탐색 |
| `botjim relay [플래그]` | 페어링 브로커 (기본 포트 4762) |
| `botjim send --via RELAY PATH...` | 릴레이로 push; 일회용 페어링 코드 출력 |
| `botjim recv --via RELAY --code CODE` | 릴레이 push를 `--dest`에 수신 |
| `botjim swarm seed\|join\|track\|verify\|keygen` | 토큰 조인 스웜 분배 |
| `botjim serve [DIR]` | HTTP+Range 브리지 |
| `botjim endpoints` / `botjim config show` | config 확인 |
| `botjim audit verify\|tail FILE` | 해시체인 저널 리더 |
| `botjim update [--check\|--force]` | 자동 업데이트 |
| `botjim completion bash\|zsh\|fish` / `botjim man` | 셸 컴플리션 / 맨페이지 |
| `botjim version` / `botjim help [cmd]` | |

서버는 `--root`를 감옥으로 삼습니다 — 수신 파일은 그 안에만, pull도 그 안에서만 읽으며 `..`/절대경로/심볼릭 링크 탈출은 거부합니다. 전송 전 디스크 여유 검사로 못 받는 파일은 처음부터 거부합니다.

## config

`~/.botjim/config.json`(또는 `$BOTJIM_CONFIG`)이 플래그 기본값과 네임드 엔드포인트를 제공합니다:

```json
{
  "token": "s3cret",
  "compress": "zstd",
  "endpoints": {
    "lab1": {"addr": "10.0.0.5:4761", "token": "lab-token"}
  },
  "autosync": {
    "lab1": {"exclude": ["*.tmp"], "delete": true, "dest": "~/mirror/lab1"}
  }
}
```

`botjim send lab1 ...`, `botjim sync push lab1`이 `lab1`을 자동 해석하며, 명시적 플래그가 항상 config보다 우선합니다.

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

## 스웜 사용 예

```
$ botjim swarm keygen                                   # 최초 1회: ed25519 스펙 서명 키
$ botjim swarm seed --tracker t.example.com model/      # 코드 + swarm id 출력, 스펙 서명
$ botjim swarm track                                    # 트래커 (아무 호스트나)
$ botjim swarm join --tracker t.example.com --code 코드 \
                     --spec model.swarm.json --dest . --serve
```

조이너도 검증 완료 데이터부터는 소스가 되므로 스웜이 점점 가속하고, rarest 청크를 우선 가져오며, `--verify-key`(서명자 공개키)로 바뀐/위조 스펙은 거부합니다.

## 성능 (루프백 tmpfs, 16코어)

| 워크로드 | botjim | `tar \| nc`(압축해제 포함) |
|---|---|---|
| 5GiB 단일 파일 (none, p=8) | **1397 MiB/s** | 1054 MiB/s |
| 5GiB 단일 (zstd-3) | 1159 MiB/s | — |
| 20k × 64KiB 소파일 | 348 MiB/s | 437 MiB/s |
| 1GiB 난수 (zstd, raw 폴백) | 1163 MiB/s | 390 MiB/s |
| 1GiB 제로(sparse) | 0.09초 (구멍은 전송 안 함) | — |

## 보안

다이렉트 모드는 옵트인 전까지 평문입니다: `--token`(공유 비밀 증명), `--pass`(레코드 레이어 암호화), `--cloak`(WebSocket으로 위장한 트래픽 성형). 릴레이와 스웜 링크는 구조적으로 종단간 암호화됩니다 — 브로커·트래커는 암호문과 메타데이터만 봅니다. 악의적 릴레이가 할 수 있는 일은 서비스 거부와 시점·크기 관찰뿐입니다. 감사 저널은 변조 방지가 되고, 영수증에는 매니페스트 다이제스트가 실립니다.

## 개발

```
make test        # 단위 + 통합 (push/pull × 압축 × 병렬 행렬, 리줌, 감옥, 릴레이)
make race        # -race
make harnesses   # 속성 하니스 + kill -9 스위트 + docker 컨테이너 E2E
make bench       # tar|nc 기준 벤치마크
```

## 라이선스

MIT — [LICENSE](LICENSE)
