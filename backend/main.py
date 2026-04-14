from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import Response
import httpx
import os
import base64
from dotenv import load_dotenv
from dss_client import sign_document, get_access_token, get_certificates, verify_signature

load_dotenv()

app = FastAPI(title="RB-Office Sign API")

JWT_SECRET = os.getenv("JWT_SECRET")
ONLYOFFICE_URL = os.getenv("ONLYOFFICE_URL")
SIGNATURES_DIR = os.getenv("SIGNATURES_DIR", "./signatures")

os.makedirs(SIGNATURES_DIR, exist_ok=True)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def root():
    return {"message": "RB-Office Sign API is running"}


@app.get("/dss/check")
async def dss_check():
    """
    Проверяет подключение к DSS:
    получает токен и список сертификатов.
    """
    try:
        token = await get_access_token()
        certs = await get_certificates(token)
        return {
            "status": "ok",
            "token_received": True,
            "certificates": [
                {
                    "id": c.get("Id"),
                    "subject": c.get("SubjectName"),
                    "is_default": c.get("IsDefault"),
                    "valid_to": c.get("ValidTo"),
                }
                for c in certs
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dss/sign-test")
async def sign_test():
    """Тестовое подписание — подписывает строку 'Hello DSS'."""
    try:
        test_content = b"Hello DSS - test signature"
        sig_bytes = await sign_document(test_content, "test.txt")
        sig_b64 = base64.b64encode(sig_bytes).decode()
        return {
            "status": "ok",
            "signature_size": len(sig_bytes),
            "signature_b64": sig_b64[:100] + "...",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dss/sign")
async def sign_endpoint(file: UploadFile = File(...)):
    """Принимает файл, возвращает отделённую подпись (.sig)."""
    try:
        file_content = await file.read()
        sig_bytes = await sign_document(file_content, file.filename)
        return Response(
            content=sig_bytes,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{file.filename}.sig"'
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/callback")
async def onlyoffice_callback(request: Request):
    """
    Callback от OnlyOffice при сохранении документа.
    Статус 2 = документ готов к скачиванию и подписанию.
    """
    body = await request.json()
    status = body.get("status")

    if status == 2:
        download_url = body.get("url")
        key = body.get("key", "unknown")

        # Скачиваем документ от OnlyOffice
        async with httpx.AsyncClient() as client:
            response = await client.get(download_url)
            file_content = response.content

        # Подписываем
        sig_bytes = await sign_document(file_content, f"{key}.docx")

        # Сохраняем подпись в постоянную директорию
        sig_path = os.path.join(SIGNATURES_DIR, f"{key}.sig")
        with open(sig_path, "wb") as f:
            f.write(sig_bytes)

        return {
            "error": 0,
            "signed": True,
            "signature_size": len(sig_bytes),
            "sig_path": sig_path,
        }

    # Остальные статусы — просто подтверждаем
    return {"error": 0}


@app.get("/dss/signatures/{key}")
async def get_signature(key: str):
    """Отдаёт .sig файл по ключу документа."""
    sig_path = os.path.join(SIGNATURES_DIR, f"{key}.sig")
    if not os.path.isfile(sig_path):
        raise HTTPException(status_code=404, detail="Подпись не найдена")
    with open(sig_path, "rb") as f:
        sig_bytes = f.read()
    return Response(
        content=sig_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{key}.sig"'},
    )


@app.post("/dss/verify")
async def verify_endpoint(
    file: UploadFile = File(..., description="Исходный документ"),
    signature: UploadFile = File(..., description="Файл подписи (.sig)"),
):
    """
    Проверяет отделённую подпись.
    Принимает два файла: оригинальный документ и .sig-файл.
    Возвращает результат верификации с информацией о подписанте.
    """
    try:
        file_content = await file.read()
        sig_content = await signature.read()
        result = await verify_signature(file_content, sig_content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
