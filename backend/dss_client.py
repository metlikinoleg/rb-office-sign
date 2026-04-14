import httpx
import base64
import os
from dotenv import load_dotenv

load_dotenv()

DSS_BASE_URL = os.getenv("DSS_BASE_URL", "https://dss.cryptopro.ru")
DSS_LOGIN = os.getenv("DSS_LOGIN")
DSS_PASSWORD = os.getenv("DSS_PASSWORD")
DSS_PIN = os.getenv("DSS_PIN", "")

OAUTH_CLIENT_ID = os.getenv("DSS_CLIENT_ID", "")
DSS_CLIENT_SECRET = os.getenv("DSS_CLIENT_SECRET", "")
OAUTH_RESOURCE = "urn:cryptopro:dss:signserver:signserver"


def check_config():
    missing = []
    if not DSS_LOGIN: missing.append("DSS_LOGIN")
    if not DSS_PASSWORD: missing.append("DSS_PASSWORD")
    if not OAUTH_CLIENT_ID: missing.append("DSS_CLIENT_ID")
    if missing:
        raise ValueError(f"Отсутствуют переменные окружения: {', '.join(missing)}")


async def get_access_token() -> str:
    """
    Получает OAuth access_token от Центра Идентификации DSS.
    Использует grant_type=password (Resource Owner Password Credentials).
    """
    check_config()
    url = f"{DSS_BASE_URL}/STS/oauth/token"

    # client_id:client_secret передаётся в Basic Auth заголовке
    secret = DSS_CLIENT_SECRET if DSS_CLIENT_SECRET else ""
    client_credentials = base64.b64encode(
        f"{OAUTH_CLIENT_ID}:{secret}".encode()
    ).decode()

    headers = {
        "Authorization": f"Basic {client_credentials}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    data = {
        "grant_type": "password",
        "username": DSS_LOGIN,
        "password": DSS_PASSWORD,
        "resource": OAUTH_RESOURCE,
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, headers=headers, data=data)
        response.raise_for_status()
        token_data = response.json()
        return token_data["access_token"]


async def get_certificates(access_token: str) -> list:
    """
    Получает список сертификатов пользователя.
    """
    url = f"{DSS_BASE_URL}/SignServer/rest/api/certificates"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


async def get_default_certificate_id(access_token: str) -> int:
    """Получает ID сертификата по умолчанию."""
    certs = await get_certificates(access_token)
    for cert in certs:
        if cert.get("IsDefault") or cert.get("is_default"):
            return cert.get("Id") or cert.get("id") or 0
    return 0


async def sign_document(file_content: bytes, file_name: str) -> bytes:
    """
    Подписывает документ через КриптоПро DSS REST API.
    Возвращает байты отделённой подписи (.sig файл).
    """
    access_token = await get_access_token()
    cert_id = await get_default_certificate_id(access_token)

    content_b64 = base64.b64encode(file_content).decode()

    payload = {
        "Content": content_b64,
        "Signature": {
            "Type": "CAdES",
            "Parameters": {
                "CADESType": "BES",
                "IsDetached": "True",
            },
            "CertificateId": cert_id,
            "PinCode": DSS_PIN,
        },
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json; charset=utf-8",
    }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            f"{DSS_BASE_URL}/SignServer/rest/api/documents",
            headers=headers,
            json=payload,
        )
        if response.status_code != 200:
            raise Exception(f"Ошибка подписания: {response.status_code} {response.text}")
        result = response.json()
        # DSS может вернуть строку base64 напрямую или объект с ключом
        if isinstance(result, str):
            return base64.b64decode(result)
        if isinstance(result, dict):
            sig_b64 = result.get("Signature") or result.get("Content")
            if sig_b64:
                return base64.b64decode(sig_b64)
        raise Exception(f"Неожиданный формат ответа DSS: {result}")


async def sign_file(file_content: bytes) -> bytes:
    """
    Обёртка для обратной совместимости с существующими endpoint-ами.
    """
    return await sign_document(file_content, "document")


async def verify_signature(file_content: bytes, signature_content: bytes) -> dict:
    """
    Проверяет отделённую подпись CAdES-BES через КриптоПро SVS REST API.
    Не требует OAuth-токена.

    Возвращает dict с полями:
      - valid: bool
      - message: str
      - signer: dict (SubjectName, IssuerName, NotBefore, NotAfter, Thumbprint)
      - signature_type: str (BES, T, XLT1...)
      - signing_time: str
    """
    source_b64 = base64.b64encode(file_content).decode()
    sig_b64 = base64.b64encode(signature_content).decode()

    payload = {
        "SignatureType": "CAdES",
        "Content": sig_b64,
        "Source": source_b64,
    }

    url = f"{DSS_BASE_URL}/verify/rest/api/signatures"

    async with httpx.AsyncClient(timeout=60, verify=True) as client:
        response = await client.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code != 200:
            raise Exception(
                f"Ошибка SVS: {response.status_code} {response.text}"
            )

        results = response.json()

    # SVS возвращает массив результатов (по одному на каждого подписанта)
    if not results or not isinstance(results, list):
        raise Exception(f"Пустой или неожиданный ответ SVS: {results}")

    first = results[0]
    cert_info = first.get("SignerCertificateInfo", {})
    sig_info = first.get("SignatureInfo", {})

    return {
        "valid": first.get("Result", False),
        "message": first.get("Message") or "Подпись действительна",
        "signer": {
            "subject": cert_info.get("SubjectName"),
            "issuer": cert_info.get("IssuerName"),
            "valid_from": cert_info.get("NotBefore"),
            "valid_to": cert_info.get("NotAfter"),
            "thumbprint": cert_info.get("Thumbprint"),
            "serial": cert_info.get("SerialNumber"),
        },
        "signature_type": sig_info.get("CAdESType"),
        "signing_time": sig_info.get("LocalSigningTime"),
    }
