# 🛡️ Phishing URL Scanner

A Python-Based Phishing Url detecion tool designed to detect and flag potentially malicious URLs using heuristic analysis and pattern-based detection techniques. This project aims to support cybersecurity efforts by identifying common phishing strategies used in deceptive web links.
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Features
* Detects obfuscated and suspicious domains
* Flags IP-based URLs
* Identifies deceptive subdomain patterns
* Detects typosquatting and known phishing tricks
* Supports blacklist/whitelist matching
* Command-line interface or API integration-ready
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Techniques Used 
* Hueristic Analysis :
  1.Check for IP address in URLs.
  2.Check for Suspicious Symbols in URLs ex: '@'.
  3.Count hyphens and detect wether it's suspicious or not.
  4.Check Url length.
  5.Check for suspicious Top-Level Domains (TLD)s e.g( xyz, top, icu, club).
  6.Check for subdomain spoofing & Trusted Domains imitation.
* Domain age check through the Whois library.
* Check the URl at the google safe browsing to see if it's blacklisted or flagged as suspicous before.

  ## Getting Started
    ### Prerequisites
          1.Python3.X
          2.pip install -r re requests tldextract json
    ### Installation
        1.Install the requirements
        2.intall the scanner file
        3.Replace the API Key with yours
  ### Running the script
        python scanner.py
    Enter a URL :
  ## Example URLs :
      * Safe : https://youtube.com
      * Suspicious : http://secure.verify.account.update.amazon.com.fake-domain.xyz/login
  ## Contribution
    Pull requests are welcome! If you have ideas to improve detection or want to expand the tool, feel free to contribute.
  ---------------------------------------------------------------------------------------------------------------------------------------------------
  # Password Strength Checker
    A comprehensive and user-friendly Password Strength Checker built with Python and Tkinter. This tool provides real-time analysis of password         security with detailed feedback and visual indicators.
  ## Features
  ### Real-time Password Analysis
     * Instant feedback as you type
     * Visual strength meter with color-coded progress bar
     * Five-level strength assessment: Very Weak, Weak, Moderate, Strong, Very Strong
     * Detailed feedback with specific improvement suggestions

  ### Advanced Security Checks
     * Length validation (8+ characters recommended)
     * Character variety analysis (uppercase, lowercase, digits, special characters)
     * Common password detection against a database of weak passwords
     * Pattern recognition (sequential characters, repeated patterns)
     * Entropy calculation for measuring unpredictability

  ### User-Friendly Interface
     * Clean, intuitive GUI built with Tkinter
     * Show/hide password toggle for convenience
     * Scrollable feedback area with comprehensive suggestions
     * Password creation tips and best practices

## Quick Start

   ## Prerequisites 
   * Python 3.6 or higher  
   * Tkinter (Usually included with python installation)

