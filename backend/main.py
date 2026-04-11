from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="RB-Office Sign API")

DSS_BASE_URL = os.getenv("DSS_BASE_URL", "https://dss.cryptopro.ru")
DSS_LOGIN = os.getenv("DSS_LOGIN")
DSS_PASSWORD = os.getenv("DSS_PASSWORD")
DSS_PIN = os.getenv("DSS_PIN")
JWT_SECRET = os.getenv("JWT_SECRET")


@app.get("/health")
async def health():
    return {"status": "ok"}


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

        file_path = f"/tmp/{key}.docx"
        with open(file_path, "wb") as f:
            f.write(file_content)

        return JSONResponse({"error": 0})

    return JSONResponse({"error": 0})


@app.get("/")
async def root():
    return {"message": "RB-Office Sign API is running"}
