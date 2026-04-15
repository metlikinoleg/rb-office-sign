from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import Response, FileResponse
import httpx
import os
import json
import base64
import uuid
import jwt
from datetime import datetime, timezone
from dotenv import load_dotenv
from dss_client import sign_document, get_access_token, get_certificates, verify_signature

load_dotenv()

app = FastAPI(title="RB-Office Sign API")

JWT_SECRET = os.getenv("JWT_SECRET")
ONLYOFFICE_URL = os.getenv("ONLYOFFICE_URL")
SIGNATURES_DIR = os.getenv("SIGNATURES_DIR", "./signatures")
DOCUMENTS_DIR = os.getenv("DOCUMENTS_DIR", "./documents")

os.makedirs(SIGNATURES_DIR, exist_ok=True)
os.makedirs(DOCUMENTS_DIR, exist_ok=True)

METADATA_FILE = os.path.join(DOCUMENTS_DIR, "metadata.json")


def _read_metadata() -> list:
    if not os.path.isfile(METADATA_FILE):
        return []
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_metadata(data: list):
    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _find_doc(docs: list, doc_id: str) -> dict | None:
    for d in docs:
        if d["id"] == doc_id:
            return d
    return None


def _get_document_type(ext: str) -> str:
    ext = ext.lower().lstrip(".")
    if ext in ("doc", "docx", "odt", "rtf", "txt", "html", "htm", "pdf"):
        return "word"
    if ext in ("xls", "xlsx", "ods", "csv"):
        return "cell"
    if ext in ("ppt", "pptx", "odp"):
        return "slide"
    return "word"


# ── Health ──────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def root():
    return {"message": "RB-Office Sign API is running"}


# ── DSS endpoints ──────────────────────────────────────────────

@app.get("/dss/check")
async def dss_check():
    """Проверяет подключение к DSS: получает токен и список сертификатов."""
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
    """Проверяет отделённую подпись (два файла: документ + .sig)."""
    try:
        file_content = await file.read()
        sig_content = await signature.read()
        result = await verify_signature(file_content, sig_content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── OnlyOffice callback ───────────────────────────────────────

@app.post("/callback")
async def onlyoffice_callback(request: Request):
    """
    Callback от OnlyOffice при событиях редактирования.
    Статус 2 = документ сохранён, все пользователи вышли — скачиваем и сохраняем.
    """
    body = await request.json()
    status = body.get("status")
    key = body.get("key", "unknown")
    print(f"[CALLBACK] status={status} key={key} body={json.dumps(body, ensure_ascii=False)}")

    if status == 2:
        download_url = body.get("url")
        if not download_url:
            print(f"[CALLBACK] ERROR: status=2 but no URL in body")
            return {"error": 0}

        # Extract doc_id from key (format: "{uuid}_{timestamp}")
        # UUID has 5 parts: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        parts = key.split("_")
        doc_id = "_".join(parts[:-1]) if len(parts) > 1 else key

        docs = _read_metadata()
        doc = _find_doc(docs, doc_id)
        if not doc:
            print(f"[CALLBACK] ERROR: document not found for doc_id={doc_id}")
            return {"error": 0}

        # Download updated document from OnlyOffice
        # URL may use internal hostname — try as-is first, then replace with container name
        file_content = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(download_url)
                response.raise_for_status()
                file_content = response.content
                print(f"[CALLBACK] Downloaded {len(file_content)} bytes from {download_url}")
            except Exception as e:
                print(f"[CALLBACK] Failed to download from {download_url}: {e}")
                # Try replacing hostname with OnlyOffice container name
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(download_url)
                alt_url = urlunparse(parsed._replace(netloc="onlyoffice"))
                try:
                    response = await client.get(alt_url)
                    response.raise_for_status()
                    file_content = response.content
                    print(f"[CALLBACK] Downloaded {len(file_content)} bytes from {alt_url}")
                except Exception as e2:
                    print(f"[CALLBACK] Also failed from {alt_url}: {e2}")

        if file_content:
            # Save updated file, overwriting the original
            file_path = os.path.join(DOCUMENTS_DIR, doc["stored_name"])
            with open(file_path, "wb") as f:
                f.write(file_content)
            print(f"[CALLBACK] Saved updated document to {file_path}")
        else:
            print(f"[CALLBACK] Could not download document, skipping save")

        return {"error": 0}

    if status == 6:
        print(f"[CALLBACK] Force save error for key={key}")

    return {"error": 0}


# ── Document management ───────────────────────────────────────

@app.post("/documents/upload")
async def upload_document(file: UploadFile = File(...)):
    """Загружает документ, сохраняет на диск, добавляет в metadata.json."""
    doc_id = str(uuid.uuid4())
    ext = os.path.splitext(file.filename or "doc")[1]
    stored_name = f"{doc_id}{ext}"
    file_path = os.path.join(DOCUMENTS_DIR, stored_name)

    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    now = datetime.now(timezone.utc).isoformat()
    docs = _read_metadata()
    docs.append({
        "id": doc_id,
        "filename": file.filename,
        "stored_name": stored_name,
        "uploaded_at": now,
        "signed": False,
        "signature_time": None,
        "signer": None,
    })
    _write_metadata(docs)

    return {"id": doc_id, "filename": file.filename, "uploaded_at": now}


@app.get("/documents")
async def list_documents():
    """Список всех документов."""
    return _read_metadata()


@app.get("/documents/{doc_id}/download")
async def download_document(doc_id: str):
    """Отдаёт файл документа."""
    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")
    file_path = os.path.join(DOCUMENTS_DIR, doc["stored_name"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Файл не найден на диске")
    return FileResponse(
        file_path,
        filename=doc["filename"],
        media_type="application/octet-stream",
    )


@app.delete("/documents/{doc_id}")
async def delete_document(doc_id: str):
    """Удаляет документ и его подпись (если есть)."""
    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")

    file_path = os.path.join(DOCUMENTS_DIR, doc["stored_name"])
    if os.path.isfile(file_path):
        os.remove(file_path)

    sig_path = os.path.join(SIGNATURES_DIR, f"{doc_id}.sig")
    if os.path.isfile(sig_path):
        os.remove(sig_path)

    docs = [d for d in docs if d["id"] != doc_id]
    _write_metadata(docs)

    return {"status": "deleted", "id": doc_id}


@app.post("/documents/{doc_id}/sign")
async def sign_doc(doc_id: str):
    """Подписывает документ через DSS, сохраняет подпись, обновляет метаданные."""
    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")

    file_path = os.path.join(DOCUMENTS_DIR, doc["stored_name"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Файл не найден на диске")

    with open(file_path, "rb") as f:
        file_content = f.read()

    sig_bytes = await sign_document(file_content, doc["filename"])

    sig_path = os.path.join(SIGNATURES_DIR, f"{doc_id}.sig")
    with open(sig_path, "wb") as f:
        f.write(sig_bytes)

    # Верифицируем чтобы получить информацию о подписанте
    verify_result = await verify_signature(file_content, sig_bytes)

    doc["signed"] = True
    doc["signature_time"] = verify_result.get("signing_time")
    doc["signer"] = verify_result.get("signer", {}).get("subject")
    _write_metadata(docs)

    return {
        "status": "signed",
        "id": doc_id,
        "signature_size": len(sig_bytes),
        "signer": doc["signer"],
        "signature_time": doc["signature_time"],
    }


@app.post("/documents/{doc_id}/verify")
async def verify_doc(doc_id: str):
    """Проверяет подпись документа."""
    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")

    file_path = os.path.join(DOCUMENTS_DIR, doc["stored_name"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Файл не найден на диске")

    sig_path = os.path.join(SIGNATURES_DIR, f"{doc_id}.sig")
    if not os.path.isfile(sig_path):
        raise HTTPException(status_code=404, detail="Подпись не найдена")

    with open(file_path, "rb") as f:
        file_content = f.read()
    with open(sig_path, "rb") as f:
        sig_content = f.read()

    result = await verify_signature(file_content, sig_content)
    return result


@app.get("/documents/{doc_id}/editor-config")
async def editor_config(doc_id: str):
    """Возвращает конфиг для OnlyOffice JS API, подписанный JWT."""
    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")

    ext = os.path.splitext(doc["filename"])[1].lstrip(".")
    editor_key = f"{doc_id}_{int(datetime.now(timezone.utc).timestamp())}"

    # URL доступный из контейнера OnlyOffice через Docker-сеть
    backend_url = "http://rb-office-backend:8000"

    config = {
        "document": {
            "fileType": ext,
            "key": editor_key,
            "title": doc["filename"],
            "url": f"{backend_url}/documents/{doc_id}/download",
        },
        "editorConfig": {
            "callbackUrl": f"{backend_url}/callback",
            "mode": "edit",
            "lang": "ru",
        },
        "documentType": _get_document_type(ext),
    }

    config["token"] = jwt.encode(config, JWT_SECRET, algorithm="HS256")

    return config
