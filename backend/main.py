from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import Response, FileResponse, StreamingResponse
from pydantic import BaseModel
import httpx
import os
import io
import json
import base64
import logging
import uuid
import jwt
from urllib.parse import quote
from datetime import datetime, timezone
from dotenv import load_dotenv
from dss_client import sign_document, get_access_token, get_certificates, verify_signature

logger = logging.getLogger("rb-office")
logging.basicConfig(level=logging.INFO)

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.platypus.flowables import Flowable
from pypdf import PdfReader, PdfWriter

import re

load_dotenv()

app = FastAPI(title="RB-Office Sign API")

JWT_SECRET = os.getenv("JWT_SECRET")
ONLYOFFICE_URL = os.getenv("ONLYOFFICE_URL")
ONLYOFFICE_INTERNAL_URL = os.getenv("ONLYOFFICE_INTERNAL_URL", "http://onlyoffice")
BACKEND_INTERNAL_URL = os.getenv("BACKEND_INTERNAL_URL", "http://rb-office-backend:8000")
SIGNATURES_DIR = os.getenv("SIGNATURES_DIR", "./signatures")
DOCUMENTS_DIR = os.getenv("DOCUMENTS_DIR", "./documents")

# Шрифт с поддержкой кириллицы — устанавливается через пакет fonts-dejavu-core
DEJAVU_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
DEJAVU_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
DEJAVU_MONO_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
_font_registered = False


def _register_fonts():
    global _font_registered
    if _font_registered:
        return
    if os.path.isfile(DEJAVU_PATH):
        pdfmetrics.registerFont(TTFont("DejaVu", DEJAVU_PATH))
    if os.path.isfile(DEJAVU_BOLD_PATH):
        pdfmetrics.registerFont(TTFont("DejaVu-Bold", DEJAVU_BOLD_PATH))
    if os.path.isfile(DEJAVU_MONO_PATH):
        pdfmetrics.registerFont(TTFont("DejaVu-Mono", DEJAVU_MONO_PATH))
    _font_registered = True

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


@app.get("/documents/{doc_id}")
async def get_document(doc_id: str):
    """Возвращает полную запись о документе из metadata.json."""
    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")
    return doc


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

    signer_info = verify_result.get("signer", {}) or {}
    doc["signed"] = True
    doc["signature_time"] = verify_result.get("signing_time")
    doc["signer"] = signer_info.get("subject")
    doc["signer_info"] = signer_info
    doc["signature_type"] = verify_result.get("signature_type") or "CAdES-BES"
    doc["signature_valid"] = bool(verify_result.get("valid"))
    doc["verify_message"] = verify_result.get("message")
    _write_metadata(docs)

    return {
        "status": "signed",
        "id": doc_id,
        "signature_size": len(sig_bytes),
        "signer": doc["signer"],
        "signature_time": doc["signature_time"],
    }


class LocalSignPayload(BaseModel):
    signature_base64: str


@app.get("/documents/{doc_id}/content-base64")
async def get_document_content_base64(doc_id: str):
    """Отдаёт содержимое документа в base64 — для клиентского подписания в браузере."""
    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")

    file_path = os.path.join(DOCUMENTS_DIR, doc["stored_name"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Файл не найден на диске")

    with open(file_path, "rb") as f:
        file_content = f.read()

    return {
        "content": base64.b64encode(file_content).decode(),
        "filename": doc["filename"],
    }


@app.post("/documents/{doc_id}/sign-local")
async def sign_doc_local(doc_id: str, payload: LocalSignPayload):
    """
    Принимает подпись, созданную в браузере через КриптоПро ЭЦП Browser plug-in.
    Сохраняет .sig, верифицирует через SVS, обновляет метаданные.
    """
    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")

    file_path = os.path.join(DOCUMENTS_DIR, doc["stored_name"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Файл не найден на диске")

    try:
        sig_bytes = base64.b64decode(payload.signature_base64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Некорректный base64: {e}")

    with open(file_path, "rb") as f:
        file_content = f.read()

    sig_path = os.path.join(SIGNATURES_DIR, f"{doc_id}.sig")
    with open(sig_path, "wb") as f:
        f.write(sig_bytes)

    verify_result = await verify_signature(file_content, sig_bytes)

    signer_info = verify_result.get("signer", {}) or {}
    doc["signed"] = True
    doc["signature_time"] = verify_result.get("signing_time")
    doc["signer"] = signer_info.get("subject")
    doc["signer_info"] = signer_info
    doc["signature_type"] = verify_result.get("signature_type") or "CAdES-BES"
    doc["signature_valid"] = bool(verify_result.get("valid"))
    doc["verify_message"] = verify_result.get("message")
    _write_metadata(docs)

    return {
        "status": "signed",
        "id": doc_id,
        "signature_size": len(sig_bytes),
        "signer": doc["signer"],
        "signature_time": doc["signature_time"],
        "verify": verify_result,
    }


class _LogoCircle(Flowable):
    """Круг 9мм с белыми буквами «РБ» — логотип RB-Office в шапке штампа."""

    def __init__(self, size: float = 9 * mm, fill: str = "#042C53", text_color: str = "#E6F1FB"):
        Flowable.__init__(self)
        self.size = size
        self.fill = fill
        self.text_color = text_color

    def wrap(self, _w, _h):
        return self.size, self.size

    def draw(self):
        c = self.canv
        r = self.size / 2
        c.setFillColor(HexColor(self.fill))
        c.circle(r, r, r, fill=1, stroke=0)
        c.setFillColor(HexColor(self.text_color))
        c.setFont("DejaVu-Bold", 10)
        # вертикально центрируем: ascender ~= 0.75 * fontSize
        c.drawCentredString(r, r - 3.1, "РБ")


def _extract_cn(subject: str) -> str:
    """Достаёт значение CN= из subject в стиле RFC 2253 / openssl."""
    if not subject:
        return ""
    m = re.search(r"(?:^|,\s*|/)CN=([^,/]+)", subject)
    return (m.group(1).strip() if m else subject).strip()


def _fmt_date_short(value: str) -> str:
    """Пытается привести произвольное представление даты к DD.MM.YYYY."""
    if not value:
        return ""
    s = str(value).strip()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%d.%m.%Y")
    except Exception:
        pass
    m = re.search(r"(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{2,4})", s)
    if m:
        d, mo, y = m.group(1), m.group(2), m.group(3)
        if len(y) == 2:
            y = "20" + y
        return f"{int(d):02d}.{int(mo):02d}.{y}"
    return s


def _fmt_sign_time(value: str) -> str:
    """«DD.MM.YYYY, HH:MM». Источники: ISO 8601 или «HH:MM DD.MM.YYYY (…)»."""
    if not value:
        return ""
    s = str(value).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.strftime("%d.%m.%Y, %H:%M")
    except Exception:
        pass
    m = re.search(r"(\d{1,2}):(\d{2})\s+(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{2,4})", s)
    if m:
        h, mi, d, mo, y = m.groups()
        if len(y) == 2:
            y = "20" + y
        return f"{int(d):02d}.{int(mo):02d}.{y}, {int(h):02d}:{int(mi):02d}"
    return s


class _StatusBadge(Flowable):
    """Зелёный бейдж «✓ Подпись верна» с закруглёнными углами."""

    def __init__(
        self,
        text: str = "Подпись верна",
        fill: str = "#EAF3DE",
        text_color: str = "#27500A",
        width: float = 33 * mm,
        height: float = 5.5 * mm,
    ):
        Flowable.__init__(self)
        self.text = text
        self.fill = fill
        self.text_color = text_color
        self.w = width
        self.h = height

    def wrap(self, _aw, _ah):
        return self.w, self.h

    def draw(self):
        c = self.canv
        c.setFillColor(HexColor(self.fill))
        c.setStrokeColor(HexColor(self.fill))
        c.roundRect(0, 0, self.w, self.h, 1.8 * mm, fill=1, stroke=0)
        c.setFillColor(HexColor(self.text_color))
        c.setFont("DejaVu-Bold", 7)
        c.drawString(2.2 * mm, self.h / 2 - 2.3, "✓ " + self.text)


def _build_signature_stamp_pdf(doc: dict) -> bytes:
    """Табличная страница-штамп в стиле rb-office.ru."""
    _register_fonts()

    registered = pdfmetrics.getRegisteredFontNames()
    font_regular = "DejaVu" if "DejaVu" in registered else "Helvetica"
    font_bold = "DejaVu-Bold" if "DejaVu-Bold" in registered else "Helvetica-Bold"
    font_mono = "DejaVu-Mono" if "DejaVu-Mono" in registered else "Courier"

    signer_info = doc.get("signer_info") or {}
    is_valid = bool(doc.get("signature_valid", True))
    subject_raw = signer_info.get("subject") or doc.get("signer") or ""
    cn = _extract_cn(subject_raw) or subject_raw or "—"

    # ── Стили абзацев для ячеек ─────────────────────────────────────
    st_header_title = ParagraphStyle(
        "h_title", fontName=font_regular, fontSize=11,
        textColor=HexColor("#1A1A1A"), leading=13,
    )
    st_header_sub = ParagraphStyle(
        "h_sub", fontName=font_regular, fontSize=8,
        textColor=HexColor("#5F5E5A"), leading=10,
    )
    st_col_header = ParagraphStyle(
        "col_h", fontName=font_regular, fontSize=8,
        textColor=HexColor("#5F5E5A"), leading=10,
    )
    st_role = ParagraphStyle(
        "role", fontName=font_bold, fontSize=9,
        textColor=HexColor("#0C447C"), leading=11,
    )
    st_org = ParagraphStyle(
        "org", fontName=font_bold, fontSize=9,
        textColor=HexColor("#1A1A1A"), leading=11,
    )
    st_org_sub = ParagraphStyle(
        "org_sub", fontName=font_regular, fontSize=8,
        textColor=HexColor("#5F5E5A"), leading=10,
    )
    st_cell = ParagraphStyle(
        "cell", fontName=font_regular, fontSize=9,
        textColor=HexColor("#1A1A1A"), leading=11,
    )
    st_mute = ParagraphStyle(
        "mute", fontName=font_regular, fontSize=9,
        textColor=HexColor("#5F5E5A"), leading=11,
    )
    st_mono = ParagraphStyle(
        "mono", fontName=font_mono, fontSize=7,
        textColor=HexColor("#1A1A1A"), leading=9,
    )
    st_small_mute = ParagraphStyle(
        "smute", fontName=font_regular, fontSize=8,
        textColor=HexColor("#5F5E5A"), leading=10,
    )

    # ── Геометрия страницы ──────────────────────────────────────────
    page_w, _page_h = A4
    margin = 15 * mm
    avail_w = page_w - 2 * margin

    # ── Шапка: лого + текст ─────────────────────────────────────────
    doc_id_text = doc.get("id") or ""
    header_right = [
        Paragraph("Документ подписан через RB-Office", st_header_title),
        Spacer(1, 1 * mm),
        Paragraph(f"Идентификатор {doc_id_text}", st_header_sub),
    ]
    header_table = Table(
        [[_LogoCircle(9 * mm), header_right]],
        colWidths=[12 * mm, avail_w - 12 * mm],
    )
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, HexColor("#D3D1C7")),
    ]))

    # ── Таблица подписей ───────────────────────────────────────────
    # Доли: РОЛЬ 12% / ОРГ 28% / ДОВЕРЕННОСТЬ 18% / СЕРТИФИКАТ 22% / ДАТА 20%
    col_widths = [avail_w * p for p in (0.12, 0.28, 0.18, 0.22, 0.20)]

    header_cells = [
        Paragraph("РОЛЬ", st_col_header),
        Paragraph("ОРГАНИЗАЦИЯ / СОТРУДНИК", st_col_header),
        Paragraph("ДОВЕРЕННОСТЬ", st_col_header),
        Paragraph("СЕРТИФИКАТ", st_col_header),
        Paragraph("ДАТА ПОДПИСАНИЯ", st_col_header),
    ]

    serial = signer_info.get("serial") or "—"
    valid_range = f"{_fmt_date_short(signer_info.get('valid_from')) or '—'} — {_fmt_date_short(signer_info.get('valid_to')) or '—'}"
    sign_time_str = _fmt_sign_time(doc.get("signature_time"))

    cert_cell = [
        Paragraph(serial, st_mono),
        Spacer(1, 1.5 * mm),
        Paragraph(valid_range, st_small_mute),
    ]

    date_cell = [
        Paragraph(sign_time_str or "—", st_cell),
        Spacer(1, 1.5 * mm),
        _StatusBadge("Подпись верна" if is_valid else "Подпись неверна",
                     fill="#EAF3DE" if is_valid else "#F7DCDC",
                     text_color="#27500A" if is_valid else "#7A1A1A"),
    ]

    org_cell = [Paragraph(cn, st_org)]
    if subject_raw and subject_raw != cn:
        org_cell += [Spacer(1, 1 * mm), Paragraph(subject_raw, st_org_sub)]

    signer_row = [
        Paragraph("Отправитель", st_role),
        org_cell,
        Paragraph("Не требуется", st_mute),
        cert_cell,
        date_cell,
    ]

    sig_table = Table(
        [header_cells, signer_row],
        colWidths=col_widths,
        repeatRows=1,
    )
    sig_table.setStyle(TableStyle([
        # Шапка колонок
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F1EFE8")),
        ("TOPPADDING", (0, 0), (-1, 0), 2.5 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 2.5 * mm),
        ("LEFTPADDING", (0, 0), (-1, 0), 3 * mm),
        ("RIGHTPADDING", (0, 0), (-1, 0), 3 * mm),
        # Строки данных
        ("VALIGN", (0, 1), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 1), (-1, -1), 4 * mm),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4 * mm),
        ("LEFTPADDING", (0, 1), (-1, -1), 3 * mm),
        ("RIGHTPADDING", (0, 1), (-1, -1), 3 * mm),
        # Разделитель над строкой подписи
        ("LINEABOVE", (0, 1), (-1, 1), 0.5, HexColor("#D3D1C7")),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, HexColor("#D3D1C7")),
    ]))

    # ── Сборка документа ───────────────────────────────────────────
    buf = io.BytesIO()
    pdf_doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=margin, rightMargin=margin,
        topMargin=margin, bottomMargin=margin,
        title="RB-Office: штамп подписи",
    )
    pdf_doc.build([header_table, Spacer(1, 4 * mm), sig_table])
    return buf.getvalue()


async def _convert_to_pdf(doc_id: str, filename: str, ext: str) -> bytes:
    """Запрашивает у OnlyOffice ConvertService конвертацию документа в PDF."""
    convert_key = f"{doc_id}_pdf_{int(datetime.now(timezone.utc).timestamp())}"

    payload = {
        "async": False,
        "filetype": ext.lower().lstrip("."),
        "outputtype": "pdf",
        "key": convert_key,
        "title": filename,
        "url": f"{BACKEND_INTERNAL_URL}/documents/{doc_id}/download",
    }
    payload["token"] = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    convert_url = f"{ONLYOFFICE_INTERNAL_URL}/ConvertService.ashx"

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            convert_url,
            json=payload,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"OnlyOffice ConvertService HTTP {resp.status_code}: {resp.text[:300]}",
            )
        try:
            result = resp.json()
        except Exception:
            raise HTTPException(
                status_code=502,
                detail=f"OnlyOffice вернул не-JSON: {resp.text[:300]}",
            )

        if result.get("error"):
            raise HTTPException(
                status_code=502,
                detail=f"OnlyOffice ConvertService error={result.get('error')}",
            )

        file_url = result.get("fileUrl")
        if not file_url:
            raise HTTPException(
                status_code=502,
                detail=f"ConvertService не вернул fileUrl: {result}",
            )

        pdf_resp = await client.get(file_url)
        pdf_resp.raise_for_status()
        return pdf_resp.content


# OnlyOffice ConvertService поддерживает конвертацию в PDF из office-форматов,
# но не из plain text. Явный белый список — чтобы давать пользователю понятную ошибку.
_PDF_CONVERTIBLE_EXTS = {
    "docx", "doc", "odt", "rtf",
    "xlsx", "xls", "ods", "csv",
    "pptx", "ppt", "odp",
    "pdf",
}


def _ascii_fallback(name: str) -> str:
    """Грубый ASCII-фоллбек для filename= в Content-Disposition."""
    return name.encode("ascii", "ignore").decode("ascii") or "document.pdf"


@app.get("/documents/{doc_id}/download-pdf")
async def download_pdf(doc_id: str):
    """Конвертирует документ в PDF и добавляет страницу-штамп с информацией о подписи."""
    logger.info("[download-pdf] start doc_id=%s", doc_id)

    docs = _read_metadata()
    doc = _find_doc(docs, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не найден")

    if not doc.get("signed"):
        raise HTTPException(status_code=400, detail="Документ не подписан")

    file_path = os.path.join(DOCUMENTS_DIR, doc["stored_name"])
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Файл не найден на диске")

    ext = os.path.splitext(doc["filename"])[1].lstrip(".").lower()
    if ext not in _PDF_CONVERTIBLE_EXTS:
        raise HTTPException(
            status_code=400,
            detail=f"Конвертация в PDF не поддерживается для файлов .{ext}",
        )

    try:
        logger.info("[download-pdf] converting via OnlyOffice: filename=%r ext=%s", doc["filename"], ext)
        orig_pdf_bytes = await _convert_to_pdf(doc_id, doc["filename"], ext)
        logger.info("[download-pdf] converted: %d bytes", len(orig_pdf_bytes))

        stamp_pdf_bytes = _build_signature_stamp_pdf(doc)
        logger.info("[download-pdf] stamp generated: %d bytes", len(stamp_pdf_bytes))

        writer = PdfWriter()
        writer.append(fileobj=io.BytesIO(orig_pdf_bytes))
        writer.append(fileobj=io.BytesIO(stamp_pdf_bytes))
        out = io.BytesIO()
        writer.write(out)
        out.seek(0)
        logger.info("[download-pdf] merged: %d bytes", len(out.getvalue()))
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("[download-pdf] failed for doc_id=%s: %s", doc_id, e)
        raise HTTPException(status_code=500, detail=f"Ошибка генерации PDF: {e}")

    base_name = os.path.splitext(doc["filename"])[0]
    out_name = f"{base_name}_signed.pdf"
    ascii_name = _ascii_fallback(out_name)
    # RFC 5987: filename= для ASCII-клиентов + filename*= для UTF-8.
    # HTTP-заголовки должны быть латин-1, поэтому кириллицу — только через %-кодирование.
    disposition = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(out_name)}"

    return StreamingResponse(
        out,
        media_type="application/pdf",
        headers={"Content-Disposition": disposition},
    )


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

    backend_url = BACKEND_INTERNAL_URL
    is_signed = bool(doc.get("signed"))

    document_cfg = {
        "fileType": ext,
        "key": editor_key,
        "title": doc["filename"],
        "url": f"{backend_url}/documents/{doc_id}/download",
    }
    if is_signed:
        document_cfg["permissions"] = {
            "edit": False,
            "download": True,
            "print": True,
            "review": False,
            "comment": False,
        }

    config = {
        "document": document_cfg,
        "editorConfig": {
            "callbackUrl": f"{backend_url}/callback",
            "mode": "view" if is_signed else "edit",
            "lang": "ru",
        },
        "documentType": _get_document_type(ext),
    }

    config["token"] = jwt.encode(config, JWT_SECRET, algorithm="HS256")

    return config
