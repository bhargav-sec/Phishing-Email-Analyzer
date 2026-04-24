"""
email_parser.py
Extracts readable email text from multiple file formats:
.txt, .eml, .msg, .pdf, .png, .jpg, .jpeg

Author: Bhargav (bhargav-sec)
"""

import os
import email
from email import policy
from io import BytesIO


def _parse_txt(content: bytes) -> str:
    """Plain text emails — just decode."""
    return content.decode("utf-8", errors="ignore")


def _parse_eml(content: bytes) -> str:
    """Parse .eml (standard email format) using Python's built-in email lib."""
    msg = email.message_from_bytes(content, policy=policy.default)

    headers = []
    for h in ["From", "To", "Cc", "Date", "Subject", "Reply-To", "Return-Path"]:
        val = msg.get(h)
        if val:
            headers.append(f"{h}: {val}")

    # Get the body — prefer plain text, fall back to HTML stripped
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                body = part.get_content()
                break
            elif ctype == "text/html" and not body:
                body = part.get_content()
    else:
        body = msg.get_content()

    return "\n".join(headers) + "\n\n" + str(body)


def _parse_msg(content: bytes) -> str:
    """Parse Outlook .msg files using extract-msg."""
    import extract_msg
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        msg = extract_msg.Message(tmp_path)
        headers = [
            f"From: {msg.sender}",
            f"To: {msg.to}",
            f"Cc: {msg.cc or ''}",
            f"Date: {msg.date}",
            f"Subject: {msg.subject}",
        ]
        return "\n".join(headers) + "\n\n" + (msg.body or "")
    finally:
        os.unlink(tmp_path)


def _parse_pdf(content: bytes) -> str:
    """Extract text from PDF using pdfplumber."""
    import pdfplumber

    text_parts = []
    with pdfplumber.open(BytesIO(content)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
    return "\n\n".join(text_parts)


def _parse_image(content: bytes) -> str:
    """OCR an image of an email using Tesseract."""
    from PIL import Image
    import pytesseract

    img = Image.open(BytesIO(content))
    return pytesseract.image_to_string(img)


def parse_email_file(filename: str, content: bytes) -> str:
    """
    Main entry point. Takes a filename and its raw bytes,
    returns the extracted email text as a string.
    """
    ext = os.path.splitext(filename.lower())[1]

    parsers = {
        ".txt": _parse_txt,
        ".eml": _parse_eml,
        ".msg": _parse_msg,
        ".pdf": _parse_pdf,
        ".png": _parse_image,
        ".jpg": _parse_image,
        ".jpeg": _parse_image,
    }

    if ext not in parsers:
        raise ValueError(
            f"Unsupported file type: {ext}. "
            f"Supported: {', '.join(parsers.keys())}"
        )

    return parsers[ext](content)


SUPPORTED_EXTENSIONS = ["txt", "eml", "msg", "pdf", "png", "jpg", "jpeg"]