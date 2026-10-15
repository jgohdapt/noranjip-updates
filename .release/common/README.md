# 공통 원격 프로그램 게시 도구

이 폴더는 공개 업데이트 저장소에 설치할 범용 게시 도구다. 직원용 프로그램 소스는 비공개 `jgohdapt/noranjip-remote`에만 둔다. 관리자·대시보드 배포는 변경하지 않는다.

공개 저장소의 `.release/common`에는 아래 파일만 넣는다.

- `tools`: manifest/common-version/package/publication/github-publication.mjs
- `tests`: manifest/package/publication/github-publication.test.mjs (합성 키와 가상 네트워크만 사용)
- `keys/server1.xml`, `keys/server2.xml`: 기존 공개 검증키
- `run-current.mjs`
- `requests/<배포ID>/request.json`, 두 프로필의 서명된 manifest·일반 ZIP·최소 provenance
- `current.json`: 실행할 배포ID와 공통 소스 commit. **이 파일을 main에 반영할 때 양쪽 실제 게시가 시작된다.**

개인화 EXE, 실제 build-result의 로컬 경로/환경, 직원 데이터, 비밀번호, 인증서 개인키, DPAPI 파일, 토큰은 공개 저장소에 넣지 않는다. GitHub Actions에서만 제공되는 토큰은 GitHub API 요청에만 붙이며 다운로드 리다이렉트에는 전달하지 않는다.

두 패키지는 같은 버전·공통 소스 commit이어야 한다. 양쪽 기존 stable의 서명과 hash를 검증하고, 두 불변 버전 패키지를 모두 게시·읽기 검증한 다음 각 stable을 갱신한다. 기존 stable manifest는 이름을 바꿔 보존하며 다른 assets는 변경하지 않는다. 기존 release의 전역 Latest 표시는 보존한다.

두 GitHub 채널을 원자적으로 동시에 바꾸지는 못한다. 부분 실패는 `publication-result.json`에 명시하며, 같은 요청 재실행은 이미 갱신한 채널을 낮추지 않는다. 이름 변경 중 실패하면 이전 canonical manifest를 복구한다. 네트워크 단절로 상태가 불확실하면 실제 asset와 서명을 확인한 뒤 재시도한다.

`common-remote-publish.yml`과 이전 원격 배포 workflow는 같은 concurrency group을 사용한다. 운영 채널을 수동으로 변경하는 다른 프로그램까지 잠그는 것은 아니므로, 실제 갱신 직전에도 manifest가 준비 시점과 같은지 재확인한다.

게시 결과는 Actions artifact와 비공개 공통 저장소의 releases 기록에 남긴다. 채널 게시 완료와 직원 PC의 다음 실행 시 적용 완료는 별개다.
