import re

from url_analyzer import analyze_url


URGENCY_PATTERNS = [
    "urgent",
    "immediately",
    "act now",
    "within 24 hours",
    "today",
    "as soon as possible",
    "final warning",
    "limited time"
]


CREDENTIAL_PATTERNS = [
    "password",
    "username",
    "login details",
    "credentials",
    "pin",
    "otp",
    "verify your identity",
    "confirm your password"
]


ACCOUNT_THREAT_PATTERNS = [
    "account suspended",
    "account blocked",
    "account will be blocked",
    "account locked",
    "unauthorized activity",
    "unusual activity",
    "security alert",
    "verify your account"
]


FINANCIAL_PATTERNS = [
    "bank account",
    "credit card",
    "debit card",
    "payment details",
    "billing information",
    "refund",
    "transaction",
    "money"
]


ACTION_PATTERNS = [
    "click here",
    "click the link",
    "login now",
    "verify now",
    "confirm now",
    "update now",
    "submit details"
]


def find_patterns(text, patterns):

    text = text.lower()

    detected = []

    sorted_patterns = sorted(
        patterns,
        key=len,
        reverse=True
    )

    matched_ranges = []


    for pattern in sorted_patterns:

        matches = re.finditer(
            re.escape(pattern),
            text
        )

        for match in matches:

            start = match.start()
            end = match.end()

            overlaps = any(
                start < existing_end
                and end > existing_start
                for existing_start, existing_end
                in matched_ranges
            )

            if not overlaps:

                detected.append(pattern)

                matched_ranges.append(
                    (start, end)
                )

                break


    return detected


def detect_urls(text):

    url_pattern = r'https?://[^\s]+|www\.[^\s]+'

    return re.findall(
        url_pattern,
        text,
        flags=re.IGNORECASE
    )


def analyze_phishing(text):

    urgency = find_patterns(
        text,
        URGENCY_PATTERNS
    )

    credentials = find_patterns(
        text,
        CREDENTIAL_PATTERNS
    )

    account_threats = find_patterns(
        text,
        ACCOUNT_THREAT_PATTERNS
    )

    financial = find_patterns(
        text,
        FINANCIAL_PATTERNS
    )

    actions = find_patterns(
        text,
        ACTION_PATTERNS
    )

    urls = detect_urls(text)


    url_analysis = [
        analyze_url(url)
        for url in urls
    ]


    risk_score = 0

    risk_score += len(urgency) * 10

    risk_score += len(credentials) * 25

    risk_score += len(account_threats) * 25

    risk_score += len(financial) * 10

    risk_score += len(actions) * 15


    url_risk_score = sum(
        result["risk_score"]
        for result in url_analysis
    )


    risk_score += min(
        url_risk_score,
        30
    )


    risk_score = min(
        risk_score,
        100
    )


    return {
        "risk_score": risk_score,
        "urgency": urgency,
        "credentials": credentials,
        "account_threats": account_threats,
        "financial": financial,
        "actions": actions,
        "urls": urls,
        "url_analysis": url_analysis
    }