from flask import Flask, render_template, request
import re
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time

app = Flask(__name__)

# Simple phishing blacklist
blacklist = [
    "phishing-test.com",
    "malicious-login.xyz",
    "fakebank-login.top"
]

def get_website_title(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        return soup.title.string.strip()
    except:
        return "Unable to fetch title"


def take_screenshot(url):
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
        driver.get(url)
        time.sleep(3)
        driver.save_screenshot("static/screenshot.png")
        driver.quit()
        return True
    except:
        return False


def check_phishing(url):

    score = 0
    reasons = []

    # HTTPS Check
    if not url.startswith("https://"):
        score += 1
        reasons.append("Does not use HTTPS")

    # URL Length
    if len(url) > 75:
        score += 1
        reasons.append("URL is too long")

    # Special Characters
    if "-" in url or "@" in url or "=" in url:
        score += 1
        reasons.append("Suspicious special characters")

    # IP Address
    if re.match(r"^http[s]?://\d{1,3}(\.\d{1,3}){3}", url):
        score += 1
        reasons.append("Uses IP address instead of domain")

    # Keywords
    keywords = ["login", "verify", "secure", "update", "free", "prize"]
    if any(k in url.lower() for k in keywords):
        score += 1
        reasons.append("Contains phishing keywords")

    # Blacklist check
    if any(b in url for b in blacklist):
        score += 2
        reasons.append("Website found in phishing blacklist")

    # Website Title Scan
    title = get_website_title(url)
    if any(k in title.lower() for k in keywords):
        score += 1
        reasons.append("Suspicious words found in website title")

    # Screenshot
    take_screenshot(url)

    # Risk score
    max_score = 7
    risk_score = int((score / max_score) * 100)

    if risk_score < 30:
        status = "Safe"
    elif risk_score < 60:
        status = "Moderate Risk"
    else:
        status = "Suspicious"

    return status, reasons, risk_score, title


@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "POST":

        url = request.form["url"]

        status, reasons, risk_score, title = check_phishing(url)

        return render_template(
            "result.html",
            url=url,
            status=status,
            reasons=reasons,
            risk_score=risk_score,
            title=title
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)