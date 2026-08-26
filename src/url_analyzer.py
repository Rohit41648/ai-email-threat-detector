import ipaddress

from urllib.parse import urlparse


# -----------------------------------
# SUSPICIOUS URL KEYWORDS
# -----------------------------------

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "bank",
    "wallet",
    "signin",
    "credential"
]


# -----------------------------------
# COMMON URL SHORTENERS
# -----------------------------------

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly"
]


# -----------------------------------
# CHECK IP ADDRESS HOSTNAME
# -----------------------------------

def is_ip_address(hostname):

    try:

        ipaddress.ip_address(hostname)

        return True

    except ValueError:

        return False


# -----------------------------------
# ANALYZE URL
# -----------------------------------

def analyze_url(url):

    normalized_url = url

    if not normalized_url.startswith(
        ("http://", "https://")
    ):

        normalized_url = (
            "http://" + normalized_url
        )


    parsed_url = urlparse(
        normalized_url
    )


    hostname = (
        parsed_url.hostname or ""
    ).lower()

    path = (
        parsed_url.path or ""
    ).lower()


    risk_score = 0

    reasons = []


    # -----------------------------------
    # NON-HTTPS CONNECTION
    # -----------------------------------

    if parsed_url.scheme != "https":

        risk_score += 10

        reasons.append(
            "URL does not use HTTPS"
        )


    # -----------------------------------
    # IP ADDRESS AS HOSTNAME
    # -----------------------------------

    if hostname and is_ip_address(hostname):

        risk_score += 25

        reasons.append(
            "IP address used instead of domain name"
        )


    # -----------------------------------
    # @ SYMBOL
    # -----------------------------------

    if "@" in url:

        risk_score += 20

        reasons.append(
            "@ symbol detected in URL"
        )


    # -----------------------------------
    # PUNYCODE DOMAIN
    # -----------------------------------

    if "xn--" in hostname:

        risk_score += 20

        reasons.append(
            "Punycode domain detected"
        )


    # -----------------------------------
    # EXCESSIVE SUBDOMAINS
    # -----------------------------------

    hostname_parts = [
        part
        for part in hostname.split(".")
        if part
    ]


    if len(hostname_parts) > 4:

        risk_score += 15

        reasons.append(
            "Excessive number of subdomains"
        )


    # -----------------------------------
    # LONG HOSTNAME
    # -----------------------------------

    if len(hostname) > 50:

        risk_score += 10

        reasons.append(
            "Unusually long hostname"
        )


    # -----------------------------------
    # URL SHORTENER
    # -----------------------------------

    if hostname in URL_SHORTENERS:

        risk_score += 15

        reasons.append(
            "URL shortening service detected"
        )


    # -----------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------

    searchable_text = (
        hostname + " " + path
    )


    detected_keywords = []


    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in searchable_text:

            detected_keywords.append(
                keyword
            )


    if detected_keywords:

        keyword_score = min(
            len(detected_keywords) * 5,
            20
        )

        risk_score += keyword_score

        reasons.append(
            "Suspicious URL keywords: "
            + ", ".join(
                detected_keywords
            )
        )


    # -----------------------------------
    # LIMIT SCORE
    # -----------------------------------

    risk_score = min(
        risk_score,
        100
    )


    return {
        "url": url,
        "hostname": hostname,
        "risk_score": risk_score,
        "reasons": reasons
    }