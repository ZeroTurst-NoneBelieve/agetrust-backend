# K-6 키오스크 폐기 목록 연동 안내

이 문서는 **#27의 현재 로컬 백엔드 구현을 기준으로 한 연동 초안**이다.
배포 완료나 최종 API 계약 승인을 뜻하지 않는다. 키오스크 앱의 다운로드·갱신·검사
기능은 아직 구현 전이다. 인증 헤더는 #42 계약에 맞춰 Bearer로 통일하기로 결정했다.
키 발급/배포와 오프라인 정책, 실제 연동 일정은 별도 후속 작업이다.

## 역할

- backend #27: 기존 VC를 폐기하고, 폐기 비트를 반영한 서명된 목록을 제공한다.
- mobile #12(K-6): 목록을 받아 검증·저장·갱신하고, 제시된 VC의 폐기 여부를 검사한다.
- backend #42: 키오스크가 판단한 결과와 `status_list_age_seconds`를 기록하는 작업이다.
  목록 다운로드나 갱신을 대신하지 않는다.

**새 VC를 키오스크에 미리 업로드하는 방식이 아니다.** 사용자가 제시한 VC에 적힌
목록 URL과 인덱스로 폐기 여부를 확인한다. 키 재바인딩과 새 VC 발급도 별도 절차다.

## 1. 목록 조회

VC JWT의 검증된 payload에서 `vc.credentialStatus`를 읽는다.

| 필드 | 현재 값 / 의미 |
| --- | --- |
| `type` | `StatusList2021Entry` |
| `statusPurpose` | `revocation` |
| `statusListCredential` | 조회할 목록의 전체 URL |
| `statusListIndex` | 0 이상의 정수를 나타내는 문자열 |

- 정식 경로: `GET /api/v1/status-lists/{id}`.
- 기존 경로: `GET /api/v1/status/{id}`도 호환 별칭으로 제공한다.
- 기존 목록의 URL은 DB에 그대로 남는다. 클라이언트가 임의로 URL을 새 경로로
  바꾸지 말고, 검증된 VC에 적힌 URL을 사용한다. 목록 JWT의 ID도 저장된 URL이다.
- 두 GET 모두 **등록된 ACTIVE 키오스크의 API Key**가 필요하다.
  매번 `Authorization: Bearer <api_key>`를 보내야 한다. 조건부 요청도 동일하다.
  `<api_key>`에는 API Key 원문만 넣는다. 사용자 로그인 JWT나 `식별자:키` 형식이 아니다.
  서버가 키 해시로 키오스크를 찾으므로 이 GET에는 식별자 본문이 필요 없다.
- 예전 `X-Kiosk-Key`만 보내면 401이며, 그 방식으로의 fallback은 지원하지 않는다.
  URL 호환 별칭을 유지하는 것과 인증 헤더 호환은 별개다.
- Swagger의 `KioskApiKey` 입력칸에는 API Key 원문만 넣는다. Swagger가 Bearer 접두어를
  붙여 전송한다. 사용자 로그인용 `HTTPBearer` 인증과 혼동하지 않는다.

```http
GET /api/v1/status-lists/1
Authorization: Bearer <api_key>
If-None-Match: W/"<이전에 받은 ETag>"
```

위 값은 형식 안내용 자리표시자다. 키는 안전하게 전달받아 기기에 보관하고 URL,
소스 코드, 로그에 넣지 않는다. 키 발급/회전 관리 API는 별도 작업이며 이번 수정이
운영 키를 자동 생성하지 않는다. 동일 키가 여러 키오스크에 등록되면 인증이 거절된다.
#42는 이와 같은 헤더 계약으로 구현할 예정이며, 인증 주체와 요청 본문 식별자의 일치
검증이 필요하다. 결과 기록 API 자체는 이 변경에 포함하지 않는다.

연동 서버는 키오스크에서 접근 가능한 주소여야 한다. `localhost`는 키오스크 자신을
가리킨다. HTTPS와 신뢰하는 발급자/서버 주소를 사용하고, 임의의 VC가 지정한 서버를
무조건 조회하지 않는다. API Key는 허용된 HTTPS 서버로만 전송하고 임의 URL이나
다른 서버로의 리다이렉트에 전달하지 않는다. `PUBLIC_BASE_URL` 수정·컨테이너 재생성만으로 기존 DB의
목록 URL이나 이미 발급된 VC의 URL이 바뀌지는 않는다.

## 2. 200 응답 검증 후 저장

본문은 JSON 객체가 아니라 `Content-Type: application/jwt`인 JWT 문자열이다.
단순 디코딩만으로 믿지 말고 다음을 모두 확인한 후 기존 캐시를 교체한다.

1. 미리 신뢰하도록 설정한 AgeTrust 발급자의 공개키로 **EdDSA 서명**을 검증한다.
   JWT가 스스로 제시한 키로 서명이 맞는다는 사실만으로 발급자를 신뢰하면 안 된다.
   대상 VC와 목록의 발급자가 허용된 발급자인지, 목록의 `iss`와 `vc.issuer`가
   일치하는지, 시간 클레임과 타입이 유효한지도 확인한다.
2. 목록의 `sub`, `jti`, `vc.id`가 대상 VC의 `statusListCredential`과 일치하는지 확인한다.
   목록 타입은 `StatusList2021Credential`, subject 타입은 `StatusList2021`이다.
   `vc.credentialSubject.statusPurpose`는 대상 VC와 같은 `revocation`이어야 한다.
3. `vc.credentialSubject.encodedList`를 **base64url 디코딩 → gzip 해제**한다.
   필요하면 base64 패딩을 복구한다. 잘못된 인코딩·gzip, 최소 16,384바이트 미만,
   인덱스 범위 초과는 검증 실패다. 응답·압축 해제 크기도 제한해 자원 고갈을 막는다.
4. 검증된 목록, 그 목록의 ETag, 성공적으로 받은 시각을 함께 저장한다.
   손상되거나 서명이 틀린 새 응답으로 기존의 검증된 캐시를 덮어쓰지 않는다.

비트는 **각 바이트의 왼쪽부터** 센다. 현재 서버와 같은 계산식은 다음과 같다.

```text
byte_index = index // 8
mask = 0x80 >> (index % 8)
revoked = (decoded_bytes[byte_index] & mask) != 0
```

| 인덱스 | 읽을 바이트 (0부터) | 마스크 |
| --- | --- | --- |
| 0 | 0 | `0x80` |
| 7 | 0 | `0x01` |
| 8 | 1 | `0x80` |

비트가 `1`이면 폐기됐으므로 거절한다. `0`은 **폐기 표시가 없다는 뜻일 뿐**이며,
VC/VP 서명·만료·Holder 증명·얼굴 대조 등 나머지 K-6 검사를 대신하지 않는다.

## 3. 갱신과 실패 처리

검증된 캐시가 있으면 저장한 ETag를 그대로 `If-None-Match`에 넣어 재조회한다.
ETag는 `W/"..."` 형태의 약한 태그이며, 내부 문자열을 해석하거나 버전 번호로 사용하지 않는다.

| 응답 | 키오스크 처리 |
| --- | --- |
| 200 | 위의 검증을 모두 통과한 새 목록·ETag로 교체한다. |
| 304 | 본문이 없다. 해당 ETag와 연결된 **검증된 목록이 이미 있을 때만** 기존 내용을 유지하고 성공 재검증 시각을 갱신한다. 캐시가 없다면 조건부 헤더 없이 다시 요청한다. |
| 401 | 키 누락·오류는 `detail.code=KIOSK_KEY_INVALID`, 비활성/폐기 키오스크는 `KIOSK_INACTIVE`다. 키/등록 상태를 점검하고 관리자에게 알린다. 재검증 성공으로 기록하거나 일반 통신 장애로 간주해 자동 PASS 처리하지 않는다. |
| 404 | 목록을 찾지 못했다. 새 정상 목록을 받은 것으로 처리하지 않는다. |
| 503 | 목록이 비었거나 손상됐다. 서버는 `Cache-Control: no-store`를 반환한다. 오류 응답을 정상 목록으로 저장하지 않는다. |
| 통신/검증 실패 | 갱신 성공 시각을 바꾸지 않는다. 기존 검증된 캐시 사용 여부는 합의한 오프라인 정책을 따른다. |

캐시가 없거나 캐시 자체가 손상됐으면 **전부 0인 목록으로 대체하거나 인증을 PASS 처리하지 않는다.**
검증된 기존 캐시를 사용하는 경우에도 이미 폐기로 확인한 VC를 다시 유효하게 취급하지 않는다.

401 본문은 `{"detail":{"code":"KIOSK_KEY_INVALID"}}` 등의 구조이며
`Cache-Control: no-store`, `WWW-Authenticate: Bearer`를 반환한다.
현재 나머지 GET 오류 본문은 404 `{"detail":"status list not found"}`,
503 `{"detail":"status list is not available"}`다. #44의 오류 형식 통일과 통합한
최종 계약은 아직 확정 전이므로, 현재 문자열을 영구적인 클라이언트 분기 키로 고정하지 않는다.

## 확정이 필요한 정책

- 현재 200/304 응답은 `Cache-Control: private, no-cache`, `Vary: Authorization`이다.
  공유 HTTP 캐시에 저장하지 않으며 개인 HTTP 캐시도 서버 재검증 후 재사용한다.
  앱이 검증된 목록을 별도 저장해 오프라인에서 사용하는 것은 별도 정책이다.
  실제 갱신 주기·재시도·시작 시 동작은 키오스크에서 구현해야 하며, ADR과 리뷰의
  주기 표현을 맞춰 최종 확정한다. HTTP 캐시 재사용 실패를 정상 200/304로 꾸미지 않는다.
- 캐시 나이는 마지막 성공 다운로드/재검증을 기준으로 관리한다. 단순 로컬 캐시 읽기나
  통신 실패로 시각을 초기화하지 않는다. 서버 `updated_at`은 내용 변경 시각이고,
  JWT `iat`는 발급 시각이므로 캐시 나이를 대신하지 않는다.
- 현재 목록 JWT에는 `exp`가 없다. 오프라인에서 오래된 검증 목록을 계속 쓸지,
  어느 시점에 경고/중단할지는 ADR-0013의 적용 정책을 팀과 확인한다. 오래된 목록을
  허용하면서 최신 폐기의 즉시 반영까지 보장할 수는 없다.
- 운영 배포 전 기존 공개 응답의 CDN/프록시 캐시를 제거하거나 만료를 확인한다.
  키를 폐기하면 이후 서버 요청은 거절되지만, 이미 받은 목록 자체가 원격 삭제되는 것은 아니다.
- Bearer 요청 계약을 공유하고, 키 배포·회전 절차 및 인증 실패 시 기기 동작은 담당자와 조율한다.

## 공동 연동 테스트

1. 유효한 키로 목록 조회가 되고, 키 누락·오류·키오스크 비활성 상태에서는 정식/기존 경로
   모두 401인지 확인한다. ETag를 보내도 인증이 생략되지 않아야 한다.
2. VC A를 발급하고 키오스크가 서명된 목록을 받아 A의 비트 `0`을 확인한다.
3. 같은 기기에 **다른 Holder 키를 재바인딩**하여 A를 폐기한다.
4. 기존 ETag로 조회해 `200`, 새로운 ETag, A의 비트 `1`을 확인한다.
5. 새 ETag로 다시 조회해 본문 없는 `304`와 검증된 캐시 유지를 확인한다.
6. 키오스크에 A를 제시해 폐기로 거절되는지 확인한다. 새 VC가 필요하면 별도로 발급한다.
7. 통신 실패·서명 오류·손상 목록·캐시 없음도 확인해 잘못된 PASS가 생기지 않는지 확인한다.

위 목록은 **함께 실행할 테스트 절차**이며 실제 키오스크 연동 통과 결과가 아니다.
백엔드 참고 테스트: `tests/test_e2e_scenarios.py`, `tests/test_vc.py`.

관련 작업: [backend #27](https://github.com/ZeroTurst-NoneBelieve/agetrust-backend/issues/27),
[mobile #12 (K-6)](https://github.com/ZeroTurst-NoneBelieve/agetrust-mobile/issues/12),
[backend #42](https://github.com/ZeroTurst-NoneBelieve/agetrust-backend/issues/42),
[ADR-0013](https://github.com/ZeroTurst-NoneBelieve/agetrust-docs/blob/main/decisions/0013-vc-revocation-statuslist.md).
