from __future__ import annotations

from typing import Any, Dict

from core.policies import detect_restricted_content

from .attachments import inspect_attachment


def build_empty_attachment_payload() -> Dict[str, Any]:
    return {
        "attachment_url": "",
        "attachment_name": "",
        "attachment_type": "",
        "attachment_extracted_text": "",
        "attachment_scan_status": "not_applicable",
        "attachment_scan_error": "",
    }


def analyze_chat_payload(content: str, file_obj=None) -> Dict[str, Any]:
    normalized_content = str(content or "").strip()
    attachment_payload = build_empty_attachment_payload()

    if file_obj is not None:
        attachment_payload = inspect_attachment(file_obj)

    attachment_text = "\n".join(
        part
        for part in [
            attachment_payload["attachment_name"],
            attachment_payload["attachment_extracted_text"],
        ]
        if part
    ).strip()

    message_flags = detect_restricted_content(normalized_content)
    attachment_flags = detect_restricted_content(attachment_text)
    moderation_flags = sorted(set(message_flags + attachment_flags))

    analysis_text = "\n".join(part for part in [normalized_content, attachment_text] if part).strip()

    return {
        "content": normalized_content,
        "blocked": bool(moderation_flags),
        "message_flags": message_flags,
        "attachment_flags": attachment_flags,
        "moderation_flags": moderation_flags,
        "analysis_text": analysis_text,
        "attachment": attachment_payload,
    }
