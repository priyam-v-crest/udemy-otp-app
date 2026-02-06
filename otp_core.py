import base64
import email
import re
import os
import json
from datetime import datetime, timezone, timedelta

import streamlit as st
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request


# ---------------- CONFIG ---------------- #

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
LABEL_NAME = "Udemy-OTP"

UDEMY_ALIASES = {
    "learning.aiml@crestinfosystems.com",
    "learning.aws@crestinfosystems.com",
    "learning.backend@crestinfosystems.com",
    "learning.mobile@crestinfosystems.com",
    "learning.node@crestinfosystems.com",
    "learning.react@crestinfosystems.com",
    "learning@crestinfosystems.com",
}

OTP_REGEX = r"(?<!\d)\d{6}(?!\d)"
OTP_EXPIRY_MINUTES = 15
COOLDOWN_MINUTES = 3


# -------- RUNTIME SAFETY STATE -------- #

otp_state = {
    # alias: {
    #   "last_otp": str,
    #   "last_sent_at": datetime,
    #   "used_otps": set()
    # }
}

# ------------------------------------- #


def get_gmail_service():
    # ---- STREAMLIT SESSION GUARD ----
    if "gmail_service" in st.session_state:
        return st.session_state["gmail_service"]

    creds = None

    # ---- LOAD TOKEN IF IT EXISTS ----
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    # ---- REFRESH TOKEN IF POSSIBLE ----
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    # ---- IF TOKEN VALID, BUILD SERVICE ----
    if creds and creds.valid:
        service = build("gmail", "v1", credentials=creds)
        st.session_state["gmail_service"] = service
        return service

    # ---- FIRST-TIME AUTH ONLY ----
    creds_dict = json.loads(st.secrets["gmail"]["credentials"])
    redirect_uri = st.secrets["gmail"]["redirect_uri"]

    flow = InstalledAppFlow.from_client_config(creds_dict, SCOPES)
    flow.redirect_uri = redirect_uri

    if "auth_url" not in st.session_state:
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            prompt="consent"
        )
        st.session_state["auth_url"] = auth_url

    st.warning("🔐 One-time Google authorization required")
    st.write("1️⃣ Open this link in a new tab:")
    st.code(st.session_state["auth_url"])

    auth_code = st.text_input(
        "2️⃣ Paste the authorization code here",
        key="auth_code",
        type="password"
    )

    if not auth_code:
        st.stop()

    # ---- EXCHANGE CODE FOR TOKEN ----
    flow.fetch_token(code=auth_code)
    creds = flow.credentials

    with open("token.json", "w") as token:
        token.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds)

    # ---- STORE SERVICE IN SESSION (THIS IS THE KEY FIX) ----
    st.session_state["gmail_service"] = service
    st.success("✅ Google authorization complete")

    return service


def get_label_id(service, label_name):
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for label in labels:
        if label["name"] == label_name:
            return label["id"]
    raise Exception(f"Label '{label_name}' not found")


def fetch_latest_message(service, label_id):
    results = service.users().messages().list(
        userId="me",
        labelIds=[label_id],
        maxResults=1
    ).execute()

    messages = results.get("messages", [])
    if not messages:
        return None

    msg = service.users().messages().get(
        userId="me",
        id=messages[0]["id"],
        format="raw"
    ).execute()

    raw = base64.urlsafe_b64decode(msg["raw"])
    return email.message_from_bytes(raw)


def extract_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
    return msg.get_payload(decode=True).decode(errors="ignore")


def extract_otp(body: str):
    matches = re.findall(OTP_REGEX, body)
    if not matches:
        return None
    if len(matches) > 1:
        raise Exception(f"Multiple OTP candidates found: {matches}")
    return matches[0]


def extract_timestamp(msg):
    date_tuple = email.utils.parsedate_tz(msg["Date"])
    return datetime.fromtimestamp(
        email.utils.mktime_tz(date_tuple),
        tz=timezone.utc
    )


def extract_udemy_alias(msg):
    to_addr = msg.get("To")
    if to_addr and to_addr.strip().lower() in UDEMY_ALIASES:
        return to_addr.strip().lower()

    been_there = msg.get("X-BeenThere")
    if been_there and been_there.strip().lower() in UDEMY_ALIASES:
        return been_there.strip().lower()

    return None


# ------------- SAFETY LAYER ------------- #

def audit_log(alias, requester, status):
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"[AUDIT] {timestamp} | {alias} | {requester} | {status}")


def enforce_expiry(age_minutes):
    if age_minutes > OTP_EXPIRY_MINUTES:
        return False, "OTP expired"
    return True, None


def enforce_reuse(alias, otp):
    state = otp_state.get(alias)
    if state and otp in state["used_otps"]:
        return False, "OTP already used"
    return True, None


def enforce_cooldown(alias):
    state = otp_state.get(alias)
    if not state or not state["last_sent_at"]:
        return True, None

    elapsed = datetime.now(timezone.utc) - state["last_sent_at"]
    if elapsed < timedelta(minutes=COOLDOWN_MINUTES):
        remaining = COOLDOWN_MINUTES - int(elapsed.total_seconds() / 60)
        return False, f"Cooldown active ({remaining} min remaining)"

    return True, None


def mark_otp_used(alias, otp):
    state = otp_state.setdefault(alias, {
        "last_otp": None,
        "last_sent_at": None,
        "used_otps": set()
    })

    state["used_otps"].add(otp)
    state["last_otp"] = otp
    state["last_sent_at"] = datetime.now(timezone.utc)


def safety_gate(alias, otp, age_minutes, requester):
    for check in (enforce_expiry, enforce_reuse, enforce_cooldown):
        ok, err = check(alias, otp) if check == enforce_reuse else (
            check(alias) if check == enforce_cooldown else check(age_minutes)
        )
        if not ok:
            audit_log(alias, requester, err.upper().replace(" ", "_"))
            return False, err

    mark_otp_used(alias, otp)
    audit_log(alias, requester, "SUCCESS")
    return True, None


# -------- STREAMLIT ENTRY FUNCTION -------- #

def get_latest_otp_for_alias(requested_alias):
    service = get_gmail_service()
    label_id = get_label_id(service, LABEL_NAME)
    msg = fetch_latest_message(service, label_id)

    if not msg:
        return False, "No Udemy OTP email found"

    body = extract_email_body(msg)
    otp = extract_otp(body)
    timestamp = extract_timestamp(msg)
    alias = extract_udemy_alias(msg)

    if not otp:
        return False, "OTP not found"

    if alias != requested_alias:
        return False, "Latest OTP is for a different account"

    now = datetime.now(timezone.utc)
    age_minutes = (now - timestamp).total_seconds() / 60

    allowed, error = safety_gate(
        alias=alias,
        otp=otp,
        age_minutes=age_minutes,
        requester="streamlit"
    )

    if not allowed:
        return False, error

    return True, {
        "otp": otp,
        "alias": alias,
        "age": int(age_minutes)
    }





