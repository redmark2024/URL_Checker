import streamlit as st
from urllib.parse import urlparse
import ssl
import socket

def check_https(url):
    return url.startswith("https://")

def check_valid_domain(url):
    valid_extensions = [
        '.com', '.org', '.net', '.info', '.biz', '.edu', '.gov', '.mil', '.int', '.pro', 
        '.us', '.uk', '.ca', '.de', '.in', '.jp', '.fr', '.au', '.br', '.ru', '.cn', 
        '.co', '.mx', '.co.uk', '.it', '.es', '.kr', '.app', '.dev', '.tech', '.store', 
        '.blog', '.shop', '.tv', '.ai', '.me', '.xyz'
    ]
    parsed_url = urlparse(url)
    return any(parsed_url.netloc.endswith(ext) for ext in valid_extensions)

def check_for_suspicious_words(url):
    suspicious_words = ['login', 'verify', 'secure', 'update', 'account']
    return any(word in url for word in suspicious_words)

def check_ssl_certificate(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        ip = socket.gethostbyname(hostname)
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as conn:
            conn.connect((ip, 443))  # Port 443 is used for HTTPS
            cert = conn.getpeercert()
        return True 
    except Exception as e:
        return False  

def is_phishing_url(url):
    if not check_https(url):
        return "Warning: No HTTPS."
    if not check_valid_domain(url):
        return "Warning: Suspicious domain extension. Should be one of the valid TLDs."
    if check_for_suspicious_words(url):
        return "Warning: Suspicious keywords (login, verify, etc.) detected."
    if not check_ssl_certificate(url):
        return "Warning: SSL certificate is invalid or cannot be verified."
    return "This URL appears safe."

# Streamlit App Layout
st.title("Phishing URL Checker")
st.write("Enter a URL below to check if it's safe or potentially a phishing URL:")

url_input = st.text_input("Enter URL", "")

if st.button("Check URL"):
    if url_input:
        result = is_phishing_url(url_input)
        st.write(f"Result for URL: **{url_input}**")
        st.write(result)
    else:
        st.write("Please enter a URL to check.")
