from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, Response
import httpx
import os
import base64
from dotenv import load_dotenv
from dss_client import sign_file, get_access_token, get_certificates

load_dotenv()

app = FastAPI(title="RB-Office Sign API")

JWT_SECRET = os.getenv("JWT_SECRET")
ONLYOFFICE_URL = os.getenv("ONLYOFFICE_URL")


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


@app.post("/dss/sign")
async def sign_endpoint(file: UploadFile = File(...)):
    """
    Принимает файл, подписывает через DSS,
    возвращает отделённую подпись (.sig).
    """
    try:
        file_content = await file.read()
        signature = await sign_file(file_content)
        filename = f"{file.filename}.sig"
        return Response(
            content=signature,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/callback")
async def onlyoffice_callback(request: Request):
    """
    Принимает callback от OnlyOffice Document Server.
    Статус 2 = документ готов к сохранению.
    """
    body = await request.json()
    status = body.get("status")
    download_url = body.get("url")
    key = body.get("key")

    if status == 2 and download_url:
        async with httpx.AsyncClient() as client:
            response = await client.get(download_url)
            file_content = response.content

        # Подписываем файл
        try:
            signature = await sign_file(file_content)
            # Сохраняем документ и подпись
            file_path = f"/tmp/{key}.docx"
            sig_path = f"/tmp/{key}.docx.sig"
            with open(file_path, "wb") as f:
                f.write(file_content)
            with open(sig_path, "wb") as f:
                f.write(signature)
        except Exception as e:
            # Логируем ошибку но возвращаем 0 чтобы OnlyOffice не ретраил
            print(f"Signing error: {e}")

        return JSONResponse({"error": 0})

    return JSONResponse({"error": 0})
