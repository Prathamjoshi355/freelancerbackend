from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Dict

from services.cloudinary import upload_file


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif", ".webp"}
TEXT_EXTENSIONS = {".txt", ".log", ".csv"}
PDF_EXTENSIONS = {".pdf"}


def infer_attachment_type(file_obj) -> str:
    content_type = str(getattr(file_obj, "content_type", "") or "").lower()
    suffix = Path(getattr(file_obj, "name", "")).suffix.lower()

    if content_type.startswith("image/") or suffix in IMAGE_EXTENSIONS:
        return "image"
    if content_type == "application/pdf" or suffix in PDF_EXTENSIONS:
        return "document"
    if content_type.startswith("text/") or suffix in TEXT_EXTENSIONS:
        return "document"
    return "attachment"


def _write_temp_file(file_obj) -> str:
    suffix = Path(getattr(file_obj, "name", "")).suffix or ".bin"
    temp_handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        for chunk in file_obj.chunks():
            temp_handle.write(chunk)
        temp_handle.flush()
    finally:
        temp_handle.close()
    return temp_handle.name


def _extract_pdf_text(temp_path: str) -> str:
    """Extract text from PDF with timeout (max 2MB, first 5 pages only)"""
    try:
        from pypdf import PdfReader
    except Exception:
        return ""

    # Skip large files
    file_size = os.path.getsize(temp_path)
    if file_size > 2 * 1024 * 1024:  # 2MB limit
        return ""

    try:
        reader = PdfReader(temp_path)
        parts = []
        # Process only first 5 pages to avoid slowness
        for i, page in enumerate(reader.pages[:5]):
            try:
                text = page.extract_text() or ""
                if text.strip():
                    parts.append(text)
            except Exception:
                continue
        return "\n".join(part.strip() for part in parts if part.strip()).strip()
    except Exception:
        return ""


def _extract_text_document(temp_path: str) -> str:
    try:
        return Path(temp_path).read_text(encoding="utf-8", errors="ignore").strip()
    except Exception:
        return ""


def inspect_attachment(file_obj) -> Dict[str, Any]:
    """Inspect attachment with file size and timeout constraints"""
    # Check file size (max 10MB)
    file_size = getattr(file_obj, "size", 0)
    if file_size > 10 * 1024 * 1024:
        return {
            "attachment_type": "attachment",
            "attachment_name": getattr(file_obj, "name", "") or "attachment",
            "attachment_extracted_text": "",
            "attachment_scan_status": "failed",
            "attachment_scan_error": "File exceeds 10MB limit",
        }

    attachment_type = infer_attachment_type(file_obj)
    original_name = getattr(file_obj, "name", "") or "attachment"
    temp_path = _write_temp_file(file_obj)
    file_obj.seek(0)

    extracted_text = ""
    scan_status = "not_applicable"
    scan_error = ""

    try:
        suffix = Path(temp_path).suffix.lower()
        if attachment_type == "image":
            # Skip OCR for large images (>2MB)
            if file_size > 2 * 1024 * 1024:
                scan_status = "skipped"
                scan_error = "Image too large for OCR processing"
            else:
                try:
                    from FreelancerChatProtection import OCRModuleError, extract_text_from_image

                    extracted_text = extract_text_from_image(temp_path, enable_enhancement=False)
                    scan_status = "completed"
                except ImportError as exc:
                    scan_status = "failed"
                    scan_error = f"OCR dependencies unavailable"
                except OCRModuleError as exc:
                    scan_status = "failed"
                    scan_error = "OCR processing failed"
                except Exception:
                    scan_status = "failed"
                    scan_error = "OCR timeout or error"
        elif suffix in PDF_EXTENSIONS:
            extracted_text = _extract_pdf_text(temp_path)
            scan_status = "completed" if extracted_text else "skipped"
            scan_error = ""
        elif suffix in TEXT_EXTENSIONS or str(getattr(file_obj, "content_type", "")).lower().startswith("text/"):
            extracted_text = _extract_text_document(temp_path)
            scan_status = "completed" if extracted_text else "skipped"
            scan_error = ""
    except Exception as exc:
        scan_status = "failed"
        scan_error = "Inspection timeout"
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    return {
        "attachment_type": attachment_type,
        "attachment_name": original_name,
        "attachment_extracted_text": extracted_text or "",
        "attachment_scan_status": scan_status,
        "attachment_scan_error": scan_error,
    }


def upload_chat_attachment(file_obj, contract_id: str) -> Dict[str, Any]:
    file_obj.seek(0)
    result = upload_file(file_obj, folder=f"forgemarket/chat/{contract_id}")
    return {
        "attachment_url": result.get("secure_url") or result.get("url") or "",
    }
