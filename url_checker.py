import streamlit as st
import requests
import re
from urllib.parse import urlparse


def check_https(url):
    if not url.lower().startswith("https://"):
        return False
    return True


def check_suspicious_patterns(url):
    suspicious_keywords = ["login", "secure", "account", "bank", "paypal", "update", "verify"]
    domain = urlparse(url).netloc
    
    for keyword in suspicious_keywords:
        if keyword in domain.lower():
            return True
    return False


def check_url(url):
    try:
        response = requests.get(url, timeout=5)
        
       
        if not check_https(url):
            return "This URL is suspicious!"
        
        
        if check_suspicious_patterns(url):
            return "This URL may be a phishing attempt due to suspicious keywords."
        
        
        if response.status_code == 200:
            return "This URL seems to be safe."
        else:
            return f"URL returned an error code: {response.status_code}. It might be suspicious."
    
    except requests.exceptions.RequestException as e:
        return f"Could not reach the URL. Error: {e}"


def main():
   
    st.title("Phishing URL Detection Tool")
    st.write("Enter a URL below to check if it is safe or suspicious.")

    
    url = st.text_input("Enter URL to check:")
    
    if st.button("Check URL"):
        if url:
            
            result = check_url(url)
           
            st.write(result)
        else:
            st.warning("Please enter a URL to check.")


if __name__ == '__main__':
    main()
