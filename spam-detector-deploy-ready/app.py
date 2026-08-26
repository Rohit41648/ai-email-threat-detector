import sys
import os

import streamlit as st


# -----------------------------------
# CONFIGURE SOURCE PATH
# -----------------------------------

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

SRC_DIR = os.path.join(
    BASE_DIR,
    "src"
)

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


from email_analyzer import analyze_email


# -----------------------------------
# STREAMLIT PAGE CONFIGURATION
# -----------------------------------

st.set_page_config(
    page_title="AI Email Threat Detector",
    page_icon="🛡️",
    layout="centered"
)


# -----------------------------------
# PAGE HEADER
# -----------------------------------

st.title("🛡️ AI Email Threat Detector")

st.subheader(
    "Spam & Phishing Risk Analysis"
)

st.write(
    """
    Analyze email content using machine learning
    and phishing risk indicators.
    """
)


st.divider()


# -----------------------------------
# EMAIL INPUT
# -----------------------------------

email_text = st.text_area(
    "Paste email content",
    placeholder=(
        "Example: Your account has been suspended. "
        "Verify your password immediately..."
    ),
    height=220
)


# -----------------------------------
# ANALYZE BUTTON
# -----------------------------------

analyze_button = st.button(
    "Analyze Email",
    type="primary",
    use_container_width=True
)


# -----------------------------------
# EMAIL ANALYSIS
# -----------------------------------

if analyze_button:

    if not email_text.strip():

        st.warning(
            "Please enter email content before analysis."
        )

    else:

        with st.spinner(
            "Analyzing email threat indicators..."
        ):

            result = analyze_email(
                email_text
            )


        classification = result[
            "classification"
        ]

        spam_probability = result[
            "spam_probability"
        ]

        phishing_risk = result[
            "phishing_risk"
        ]

        details = result[
            "phishing_details"
        ]


        st.divider()


        # -----------------------------------
        # FINAL CLASSIFICATION
        # -----------------------------------

        st.subheader(
            "Analysis Result"
        )


        if classification == "SAFE":

            st.success(
                "✅ SAFE EMAIL"
            )

        elif classification == "SPAM":

            st.warning(
                "⚠️ SPAM DETECTED"
            )

        else:

            st.error(
                "🚨 PHISHING RISK DETECTED"
            )


        # -----------------------------------
        # RISK METRICS
        # -----------------------------------

        col1, col2 = st.columns(2)


        with col1:

            st.metric(
                "Spam Probability",
                f"{spam_probability:.2f}%"
            )


        with col2:

            st.metric(
                "Phishing Risk Score",
                f"{phishing_risk}/100"
            )


        # -----------------------------------
        # RISK PROGRESS
        # -----------------------------------

        st.write(
            "### Phishing Risk Level"
        )

        st.progress(
            phishing_risk / 100
        )


        # -----------------------------------
        # DETECTED INDICATORS
        # -----------------------------------

        st.write(
            "### Detected Security Indicators"
        )


        indicator_found = False


        if details["urgency"]:

            indicator_found = True

            st.warning(
                "⏱️ Urgency language detected: "
                + ", ".join(
                    details["urgency"]
                )
            )


        if details["credentials"]:

            indicator_found = True

            st.error(
                "🔑 Credential request detected: "
                + ", ".join(
                    details["credentials"]
                )
            )


        if details["account_threats"]:

            indicator_found = True

            st.error(
                "🔒 Account threat detected: "
                + ", ".join(
                    details["account_threats"]
                )
            )


        if details["financial"]:

            indicator_found = True

            st.warning(
                "💳 Financial language detected: "
                + ", ".join(
                    details["financial"]
                )
            )


        if details["actions"]:

            indicator_found = True

            st.warning(
                "👆 Suspicious action request detected: "
                + ", ".join(
                    details["actions"]
                )
            )


            if details.get("urls"):

                indicator_found = True

                st.write(
                    "#### 🔗 URL Analysis"
                )

                url_analysis = details.get(
                    "url_analysis",
                    []
                )

                if url_analysis:

                    for url_result in url_analysis:

                        url = url_result.get(
                            "url",
                            "Unknown URL"
                        )

                        url_risk = url_result.get(
                            "risk_score",
                            0
                        )

                        reasons = url_result.get(
                            "reasons",
                            []
                        )

                        st.write(
                            f"**URL:** {url}"
                        )

                        st.write(
                            f"URL Suspicion Score: {url_risk}/100"
                        )

                        if reasons:

                            for reason in reasons:

                                st.warning(
                                    f"⚠️ {reason}"
                                )

                        else:

                            st.info(
                                "No suspicious structural URL indicators detected."
                            )

                else:

                    for url in details.get("urls", []):

                        st.warning(
                            f"🔗 URL detected: {url}"
                        )

        if not indicator_found:

            st.success(
                "No major phishing indicators detected."
            )


        # -----------------------------------
        # SECURITY RECOMMENDATION
        # -----------------------------------

        st.write(
            "### Security Recommendation"
        )


        if classification == "PHISHING":

            st.error(
                """
                Do not click links or provide credentials.
                Verify the sender through an official channel.
                """
            )


        elif classification == "SPAM":

            st.warning(
                """
                This message shows spam-like patterns.
                Avoid responding to unsolicited offers.
                """
            )


        else:

            st.info(
                """
                No significant threat pattern was detected.
                Always verify unexpected requests.
                """
            )


# -----------------------------------
# FOOTER
# -----------------------------------

st.divider()

st.caption(
    "Hybrid ML and rule-based email threat analysis system."
)