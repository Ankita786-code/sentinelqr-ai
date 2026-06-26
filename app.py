from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

import os
from urllib.parse import urlparse

from qr_engine.qr_decoder import decode_qr

from threat_engine.url_analyzer import analyze_url
from threat_engine.blacklist_checker import check_blacklist

from models.predict import predict_url

from database.analytics import (
    save_scan,
    get_stats
)

# ----------------------------------
# APP CONFIG
# ----------------------------------

app = Flask(__name__)

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

app.config["UPLOAD_FOLDER"] = (
    UPLOAD_FOLDER
)

ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg"
}

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

# ----------------------------------
# FILE CHECK
# ----------------------------------


def allowed_file(filename):

    return (

        "." in filename

        and

        filename.rsplit(
            ".",
            1
        )[1].lower()

        in

        ALLOWED_EXTENSIONS

    )


# ----------------------------------
# DOMAIN EXTRACT
# ----------------------------------


def get_domain(url):

    parsed = urlparse(url)

    if parsed.netloc:

        return parsed.netloc.replace(
            "www.",
            ""
        )

    return url


# ----------------------------------
# RESULT GENERATOR
# ----------------------------------


def generate_result(score):

    if score <= 30:

        return (

            "Safe",

            "Low",

            "Open Normally"

        )

    elif score <= 60:

        return (

            "Suspicious",

            "Medium",

            "Open Carefully"

        )

    else:

        return (

            "Malicious",

            "High",

            "Block Website"

        )


# ----------------------------------
# HOME
# ----------------------------------


@app.route("/")

def home():

    return render_template(
        "index.html"
    )


# ----------------------------------
# SCAN
# ----------------------------------


@app.route(
    "/scan",
    methods=["POST"]
)

def scan():

    try:

        if "qr_image" not in request.files:

            return (
                "Upload image first"
            )

        file = request.files[
            "qr_image"
        ]

        if file.filename == "":

            return (
                "No image selected"
            )

        if not allowed_file(
            file.filename
        ):

            return (
                "Only PNG JPG JPEG allowed"
            )

        filename = secure_filename(
            file.filename
        )

        path = os.path.join(

            app.config[
                "UPLOAD_FOLDER"
            ],

            filename
        )

        file.save(
            path
        )

        # ------------------
             # ------------------
        # Decode QR
        # ------------------

        qr = decode_qr(path)
        print("QR DATA =", qr)

        # QR not detected
        if not qr:
            total, users, top = get_stats()

            return render_template(
                "result.html",
                url="-",
                domain="-",
                status="Invalid QR",
                severity="-",
                risk_score=0,
                confidence=0,
                recommendation="Please upload a QR code containing a website URL.",
                reasons=["QR code not detected or unreadable."],
                total=total,
                users=users,
                top=top
            )

        url = qr.strip()
        print("URL =", url)

        # Reject non-website QR codes
        if not url.startswith(("http://", "https://")):
            total, users, top = get_stats()

            return render_template(
                "result.html",
                url="-",
                domain="-",
                status="Invalid QR",
                severity="-",
                risk_score=0,
                confidence=0,
                recommendation="This QR code does not contain a website URL.",
                reasons=["The QR code contains plain text instead of a website link."],
                total=total,
                users=users,
                top=top
            )

        domain = get_domain(url)
    

        # ------------------

        risk_score, reasons = (
            analyze_url(
                url
            )
        )

        # BLACKLIST

        if check_blacklist(
            domain
        ):

            risk_score += 40

            reasons.append(

                "Blacklisted Domain"

            )

        # ML

        prediction, confidence = (

            predict_url(
                url
            )

        )

        if prediction == 1:

            risk_score += 30

            reasons.append(

                f"AI detected phishing ({confidence}%)"

            )

        risk_score = min(
            risk_score,
            100
        )

        status, severity, recommendation = (

            generate_result(
                risk_score
            )

        )

        # ------------------

        ip = request.remote_addr

        print("Saving scan:", ip, url, risk_score)

        save_scan(
            ip,
            url,
            risk_score
        )

        total, users, top = (

            get_stats()

        )

        return render_template(

            "result.html",

            url=url,

            domain=domain,

            status=status,

            severity=severity,

            risk_score=risk_score,

            confidence=confidence,

            recommendation=recommendation,

            reasons=reasons,

            total=total,

            users=users,

            top=top

        )

    except Exception as e:

        return f"Error: {str(e)}"


# ----------------------------------
# DASHBOARD
# ----------------------------------


@app.route(
    "/dashboard"
)

def dashboard():

    total, users, top = (

        get_stats()

    )

    return render_template(

        "dashboard.html",

        total=total,

        users=users,

        top=top

    )


# ----------------------------------
# RUN
# ----------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
