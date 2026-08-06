from flask import Flask, render_template, request
from utils.detector import analyze_url

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form["url"]

    result = analyze_url(url)

    # Static AI explanation
    result["ai"] = (
        "The URL was analyzed using multiple phishing indicators such as "
        "domain structure, protocol, suspicious keywords, URL length, "
        "top-level domain, and other security heuristics. Based on these "
        "indicators, the website has been assigned the displayed risk score."
    )

    # Safety tips
    result["tips"] = [
        "Verify the website's domain before entering credentials.",
        "Avoid downloading files from suspicious websites.",
        "Use HTTPS whenever possible.",
        "Enable Two-Factor Authentication (2FA)."
    ]

    # Decide the color based on the risk score
    if result["score"] >= 70:
        color = "danger"
    elif result["score"] >= 33:
        color = "warning"
    else:
        color = "safe"

    return render_template(
        "result.html",
        url=url,
        result=result,
        color=color
    )


if __name__ == "__main__":
    app.run(debug=True)