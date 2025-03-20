import streamlit as st
from urllib.parse import urlparse

def check_https(url):
    return url.startswith("https://")

def check_domain(url):
    trusted_domains = ["paypal.com", "amazon.com", "google.com"]
    parsed_url = urlparse(url)
    return parsed_url.netloc in trusted_domains

def check_for_phishing_patterns(url):
    suspicious_patterns = ['@', 'secure', 'login', 'account', 'update', 'verify']
    return any(pattern in url for pattern in suspicious_patterns)

def check_subdomains(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return len(domain.split('.')) > 2

def check_url_complexity(url):
    parsed_url = urlparse(url)
    return len(parsed_url.path) > 50

def is_phishing_url(url):
    if not check_https(url):
        return "Warning: No HTTPS."
    if not check_domain(url):
        return "Warning: Suspicious domain."
    if check_for_phishing_patterns(url):
        return "Warning: Suspicious patterns."
    if check_subdomains(url):
        return "Warning: Unusual subdomains."
    if check_url_complexity(url):
        return "Warning: URL too complex."
    return "This URL appears safe."

# Streamlit App Layout
st.title("Phishing URL Checker")
st.write("Enter a URL below to check if it's safe or potentially a phishing URL:")

url_input = st.text_input("Enter URL", "")

# Add a button that checks the URL
if st.button("Check URL"):
    if url_input:
        result = is_phishing_url(url_input)
        st.write(f"Result for URL: **{url_input}**")
        st.write(result)
    else:
        st.write("Please enter a URL to check.")
