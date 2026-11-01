
import re
import os
import joblib
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = joblib.load(os.path.join(BASE_DIR, "scam_model.pkl"))
vectorizer = joblib.load(os.path.join(BASE_DIR, "vectorizer.pkl"))


def analyze_input(value, kind="auto"):

    value = str(value or "").strip()
    kind = str(kind or "auto").lower()
    lower_value = value.lower()

    if not value:
        return {
            "verdict": "Invalid Input",
            "risk_level": "Unknown",
            "input_type": kind,
            "risk_count": 0,
            "risk_signals": [],
            "notes": "Please enter a URL or message.",
            "disclaimer": "AI predictions are not guaranteed."
        }

    if kind not in ("auto", "url", "message"):
        return {
            "verdict": "Invalid Input",
            "risk_level": "Unknown",
            "input_type": "Unknown",
            "risk_count": 0,
            "risk_signals": [],
            "notes": "Invalid input type.",
            "disclaimer": "AI predictions are not guaranteed."
        }

    signals = []

    suspicious_words = [
        "urgent", "verify your account", "password",
        "click here", "claim prize", "free money",
        "bank details", "send otp", "limited time",
        "account suspended", "confirm your identity",
        "login immediately", "payment required"
    ]

    for word in suspicious_words:
        if word in lower_value:
            signals.append(f"Suspicious phrase: {word}")

    is_url = (
        kind == "url"
        or (
            kind == "auto"
            and " " not in value
            and bool(
                re.match(
                    r"^(https?://|www\.)|^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/|$)",
                    lower_value
                )
            )
        )
    )

    if is_url:

        candidate = value

        if not candidate.startswith(("http://", "https://")):
            candidate = "https://" + candidate

        try:
            parsed = urlparse(candidate)
            hostname = parsed.hostname or ""
        except ValueError:
            hostname = ""

        if not hostname or "." not in hostname:
            return {
                "verdict": "Invalid URL",
                "risk_level": "Unknown",
                "input_type": "URL",
                "risk_count": 0,
                "risk_signals": [],
                "notes": "Please enter a valid URL.",
                "disclaimer": "AI predictions are not guaranteed."
            }

        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname):
            signals.append("URL uses an IP address")

        if "@" in parsed.netloc:
            signals.append("URL contains an @ symbol")

        if hostname.startswith("xn--") or ".xn--" in hostname:
            signals.append("Internationalized domain detected")

        if hostname.count("-") >= 3:
            signals.append("Domain contains several hyphens")

        if len(hostname) > 45:
            signals.append("Unusually long domain name")

        features = vectorizer.transform([value])
        prediction = int(model.predict(features)[0])

        # Dataset labels must be verified:
        # 0 = phishing, 1 = legitimate

        if prediction == 0:
            verdict = "Potential Scam"
            risk_level = "High"
            signals.append(
                "Machine Learning model classified this URL as potentially phishing"
            )

        elif prediction == 1:
            verdict = "No obvious warning signs"
            risk_level = "Medium" if signals else "Low"

        else:
            verdict = "Unknown"
            risk_level = "Unknown"

        notes = (
            "URL analyzed using the trained Machine Learning model "
            "and additional security checks."
        )

    else:

        if signals:
            verdict = "Suspicious Message"
            risk_level = "High" if len(signals) >= 3 else "Medium"
        else:
            verdict = "No obvious warning signs"
            risk_level = "Low"

        notes = "Message analyzed using rule-based checks."

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "input_type": "URL" if is_url else "Message",
        "risk_count": len(signals),
        "risk_signals": signals,
        "notes": notes,
        "disclaimer": (
            "This tool cannot guarantee that a URL or message is safe."
        )
    }
