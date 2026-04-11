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

    # client_id передаётся в Basic Auth заголовке: Base64(client_id:)
    client_credentials = base64.b64encode(
        f"{OAUTH_CLIENT_ID}:".encode()
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
    Используется для получения cert_id.
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


async def sign_document(
    file_content: bytes,
    access_token: str,
    cert_id: int = 0,
) -> bytes:
    """
    Подписывает документ через REST API Сервиса Подписи DSS.
    Возвращает отделённую подпись (CAdES-BES) в байтах.

    cert_id=0 означает использование сертификата по умолчанию.
    """
    url = f"{DSS_BASE_URL}/SignServer/rest/api/documents"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json; charset=utf-8",
    }

    # Документ передаётся в Base64
    content_b64 = base64.b64encode(file_content).decode()

    payload = {
        "Content": content_b64,
        "Signature": {
            "Type": "CAdES",
            "Parameters": {
                "Hash": "False",
                "CADESType": "BES",
                "IsDetached": "True",
            },
            "CertificateId": cert_id,
            "PinCode": DSS_PIN,
        },
    }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        # Ответ — Base64-строка подписи
        signature_b64 = response.json()
        return base64.b64decode(signature_b64)


async def sign_file(file_content: bytes) -> bytes:
    """
    Полный цикл подписания:
    1. Получить токен
    2. Получить cert_id сертификата по умолчанию
    3. Подписать документ
    Возвращает байты отделённой подписи (.sig)
    """
    # Шаг 1: получить токен
    access_token = await get_access_token()

    # Шаг 2: получить список сертификатов, найти default
    certs = await get_certificates(access_token)
    cert_id = 0  # 0 = сертификат по умолчанию
    for cert in certs:
        if cert.get("IsDefault"):
            cert_id = cert.get("Id", 0)
            break

    # Шаг 3: подписать
    signature = await sign_document(file_content, access_token, cert_id)
    return signature
