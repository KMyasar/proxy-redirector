# Proxy-redirector

This project showcases a  MITMProxy addon script for real-time HTTP interception, redirection, content rewriting, and request blocking — designed to simulate enterprise-grade proxy behavior and web traffic filtering.

## Features

- Domain-based HTTP redirection
- Blocking of known trackers and ad hosts
- Response content filtering and keyword redaction
- Injection of custom security headers
- Real-time request/response logging with timestamps
- Modular and extensible MITMProxy add on architecture

## Use Cases

- Simulating proxy-based security policies
- Red team traffic manipulation demos
- Dynamic content rewriting for testing
- Blocking malicious or privacy-invasive domains

## Requirements

- Python 3.7+
- [MITMProxy](https://mitmproxy.org/)

## Installation

```bash
pip install mitmproxy
```
## Usage
```bash
mitmproxy -s advanced_mitm_interceptor.py
```
You can also use mitmweb  for a web interface:

```bash
mitmweb -s advanced_mitm_interceptor.py
```
##  Files

-   `mitm_interceptor.py`: Main MITMProxy addon script
    

## Note

-   Modify the  `REDIRECT_DOMAINS`,  `BLOCKED_HOSTS`, or  `REPLACE_KEYWORDS`  as needed for custom behavior.
    

----------

**Author:**  [Mohamed Yasar Arafath](https://github.com/KMyasar)  
**Portfolio:** [yasar-arafath.web.app](https://yasar-arafath.web.app)