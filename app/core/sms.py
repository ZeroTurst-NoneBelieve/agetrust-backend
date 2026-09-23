"""SOLAPI를 통한 전화번호 인증 OTP 발송.

OTP 생성·만료·검증은 AgeTrust가 담당하고, 이 모듈은 전달만 맡는다.
SOLAPI Python SDK는 동기식이므로 async API의 이벤트 루프를 막지 않도록
실제 호출을 작업 스레드에서 실행한다.
"""

import asyncio
import re
from dataclasses import dataclass

from solapi import SolapiMessageService
from solapi.error.MessageNotReceiveError import MessageNotReceivedError
from solapi.model import MessageType, RequestMessage, SendRequestConfig

from app.config import settings

_KOREAN_MOBILE_E164 = re.compile(r"^\+8210\d{8}$")
_SOLAPI_SENDER = re.compile(r"^\d{8,12}$")


class SmsConfigurationError(RuntimeError):
    """실제 SMS 발송에 필요한 서버 설정이 없거나 잘못됐다."""


class SmsDeliveryError(RuntimeError):
    """SOLAPI가 SMS를 접수하지 못했다."""

    def __init__(
        self,
        provider_code: str = "UNKNOWN",
        *,
        may_have_been_sent: bool = True,
    ):
        super().__init__("SOLAPI did not accept the SMS")
        self.provider_code = provider_code
        # 네트워크 응답을 받지 못한 경우 SOLAPI가 실제로 접수했을 수도 있다.
        # 이때는 OTP와 발송량 예약을 보수적으로 유지해야 한다.
        self.may_have_been_sent = may_have_been_sent


@dataclass(frozen=True)
class SmsReceipt:
    """SOLAPI 접수 식별자. 최종 단말 수신 성공을 뜻하지는 않는다."""

    group_id: str
    message_id: str | None


def _to_solapi_recipient(phone_number: str) -> str:
    """AgeTrust의 한국 E.164 번호를 SOLAPI 국내 번호 형식으로 바꾼다."""
    if not _KOREAN_MOBILE_E164.fullmatch(phone_number):
        raise SmsDeliveryError("UNSUPPORTED_RECIPIENT", may_have_been_sent=False)
    return f"0{phone_number[3:]}"


def _provider_code(exc: Exception) -> str:
    """로그에 비밀값이나 공급자 본문을 남기지 않고 오류 코드만 추린다."""
    failed_messages = getattr(exc, "failed_messages", None)
    if failed_messages:
        code = getattr(failed_messages[0], "status_code", None)
        if code:
            return str(code)[:64]
    if exc.args and isinstance(exc.args[0], str):
        code = exc.args[0]
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", code):
            return code
    return type(exc).__name__[:64]


def _is_definitive_provider_rejection(exc: Exception, provider_code: str) -> bool:
    """고정한 SOLAPI SDK가 4xx 응답을 표현하는 형태인지 판별한다."""
    return (
        len(exc.args) >= 2
        and isinstance(exc.args[0], str)
        and exc.args[0] == provider_code
        and provider_code != "UnknownError"
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", provider_code) is not None
    )


def _solapi_credentials() -> tuple[str, str, str]:
    api_key = settings.solapi_api_key
    api_secret = settings.solapi_api_secret
    sender = (settings.solapi_sender or "").strip().replace("-", "")

    if (
        api_key is None
        or api_secret is None
        or not api_key.get_secret_value().strip()
        or not api_secret.get_secret_value().strip()
        or not sender
    ):
        raise SmsConfigurationError("SOLAPI credentials and sender are required")
    if not _SOLAPI_SENDER.fullmatch(sender):
        raise SmsConfigurationError("SOLAPI_SENDER must contain 8-12 digits")

    return (
        api_key.get_secret_value().strip(),
        api_secret.get_secret_value().strip(),
        sender,
    )


def validate_sms_configuration() -> None:
    """실제 발송을 준비하기 전에 SOLAPI 설정을 빠르게 검증한다."""
    _solapi_credentials()


def _send_otp_sms_sync(phone_number: str, otp: str) -> SmsReceipt:
    api_key, api_secret, sender = _solapi_credentials()
    recipient = _to_solapi_recipient(phone_number)
    text = f"[AgeTrust] 인증번호는 {otp}입니다. {settings.otp_expire_minutes}분 안에 입력해 주세요."

    try:
        service = SolapiMessageService(api_key=api_key, api_secret=api_secret)
        response = service.send(
            RequestMessage(
                from_=sender,
                to=recipient,
                text=text,
                # 짧은 OTP 문구가 설정 변경으로 LMS로 승격되어 비용이 늘지
                # 않도록 단문 문자로 명시한다.
                type=MessageType.SMS,
                auto_type_detect=False,
            ),
            SendRequestConfig(show_message_list=True),
        )
    except MessageNotReceivedError as exc:
        raise SmsDeliveryError(
            _provider_code(exc),
            may_have_been_sent=False,
        ) from exc
    except Exception as exc:
        provider_code = _provider_code(exc)
        raise SmsDeliveryError(
            provider_code,
            may_have_been_sent=not _is_definitive_provider_rejection(
                exc,
                provider_code,
            ),
        ) from exc

    count = response.group_info.count
    if count.total != 1:
        raise SmsDeliveryError("INVALID_RESPONSE")
    if count.registered_success != 1:
        raise SmsDeliveryError("NOT_REGISTERED", may_have_been_sent=False)
    group_id = response.group_info.group_id
    if not group_id:
        raise SmsDeliveryError("INVALID_RESPONSE")

    return SmsReceipt(
        group_id=group_id,
        message_id=response.message_list[0].message_id if response.message_list else None,
    )


async def send_otp_sms(phone_number: str, otp: str) -> SmsReceipt:
    """OTP 문자 한 건을 SOLAPI에 접수한다."""
    return await asyncio.to_thread(_send_otp_sms_sync, phone_number, otp)
