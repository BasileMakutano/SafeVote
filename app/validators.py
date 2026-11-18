"""Server-side input validation. Every form is also constrained in HTML
(required, pattern, minlength, maxlength), but the server never trusts that."""
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

NAME_RE = re.compile(r"^[^\W\d_]+(?:[ '\-][^\W\d_]+)*$")
STUDENT_ID_RE = re.compile(r"^[A-Za-z0-9\-]{4,20}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd123", "1234567890",
    "qwertyuiop", "letmein123", "welcome123", "admin12345", "iloveyou123",
}


def clean_line(raw):
    return re.sub(r"\s+", " ", raw or "").strip()


def validate_text(raw, label, min_len, max_len, multiline=False, required=True):
    value = (raw or "").replace("\r\n", "\n").strip() if multiline else clean_line(raw)
    if not value:
        return "", (f"{label} is required." if required else None)
    if CTRL_RE.search(value):
        return value, f"{label} contains characters that are not allowed."
    if not (min_len <= len(value) <= max_len):
        return value, f"{label} must be between {min_len} and {max_len} characters."
    return value, None


def validate_person_name(raw):
    value, err = validate_text(raw, "Name", 2, 80)
    if not err and not NAME_RE.match(value):
        err = "Name may contain letters, spaces, hyphens and apostrophes only."
    return value, err


def validate_student_id(raw):
    value = clean_line(raw)
    if not STUDENT_ID_RE.match(value):
        return value, "Student ID must be 4 to 20 letters, digits or hyphens."
    return value.upper(), None


def validate_email(raw, allowed_domain=""):
    value = clean_line(raw).lower()
    if len(value) > 254 or not EMAIL_RE.match(value):
        return value, "Enter a valid email address."
    if allowed_domain and not value.endswith("@" + allowed_domain):
        return value, f"Use your @{allowed_domain} email address."
    return value, None


def validate_password(password, email="", student_id=""):
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if len(password) > 128:
        return "Password must be at most 128 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain at least one letter and one number."
    low = password.lower()
    local = email.split("@")[0] if email else ""
    if (
        low in COMMON_PASSWORDS
        or (student_id and student_id.lower() in low)
        or (len(local) >= 4 and local in low)
    ):
        return "That password is too easy to guess. Avoid common words, your email or your ID."
    return None


def parse_local_datetime(raw, tz_name):
    """Parse an HTML datetime-local value in the election timezone, return UTC."""
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            naive = datetime.strptime((raw or "").strip(), fmt)
        except ValueError:
            continue
        return naive.replace(tzinfo=ZoneInfo(tz_name)).astimezone(timezone.utc)
    return None


def parse_roll(text, limit=5000):
    """Parse 'student_id,full name' lines. Returns (rows, errors)."""
    rows, errors = [], []
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if len(lines) > limit:
        return [], [f"Upload at most {limit} lines at a time."]
    for number, line in enumerate(lines, start=1):
        sid_raw, _, name_raw = line.partition(",")
        sid, sid_err = validate_student_id(sid_raw)
        name, name_err = validate_person_name(name_raw)
        if sid_err or name_err:
            errors.append(f"Line {number}: {sid_err or name_err}")
        else:
            rows.append((sid, name))
    return rows, errors
