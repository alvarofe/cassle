Advanced Architecture to validate TLS certificates
<https://github.com/alvarofe/certs-mitm>

Introduction
============

The aim of this work is to try validate each tls-connection with different techniques that exist nowadays. We are living in a world that everything is connected through internet and to provide security on this connections the mayority of them use TLS. But we have seen how some governments use different aproach to circumvent them. Some of this vulnerability can be due to bugs in the implementation, bad deployments ... etc, but one of the vulnerability that this work try to resolve is the bad or poor validation of certificates.

Before to send our private data to the other entity, usually in TLS, we have to validate the authenticity of the server with the goal to know that it is who claim it is. We have seen how apple failed in this due to the famous goto fail bug  <https://www.imperialviolet.org/2014/02/22/applebug.html>. Although is true that this vulnerability is because of bad implementation is true that if apple provide other techniques this situation could be discovered before. Our goal will be to validate each connection with different techniques because maybe an approach says that our connection is secured but perhaps there is another one that says the opposite providing a better solution.

Techniques
==========

A continuation the list of different techniques that the project is using:
* RFC - to validate in this way we are using the library nss
* SSLBlacklist - <https://sslbl.abuse.ch/blacklist/>
* Revoke status - OCSP
* DNSSEC-TLSA
* ICSI-NOTARY - <http://notary.icsi.berkeley.edu/>
* Certificate-transparency - <http://www.certificate-transparency.org/>
* Pinning


Installation
============

  Prerequisites
  -------------
  * Python >= 2.7 (www.python.org)
  * libpcap-python - <http://sourceforge.net/projects/pylibpcap/>
  * Python binding for NSS - **$ pip install python-nss**
  * M2Crypto - **$ pip install M2Crypto**
  * pyasn1 - **$ pip install pyasn1**
  * pync - Python Wrapper for Mac OS 10.8 Notification Center - **$ pip install pync** (This is only for Mac OS X)
  * Termcolor - **$ pip install termcolor**
  * pymongo - **$ pip install pymongo** (we must have installed mongo in our computer before <http://www.mongodb.org/> )
  * python-wget **$ pip install wget**
  * config **$ pip install config**

---
Once installed all packages: **./sniff.py -i < interface to sniff >**


State
=====
This project is under development and is possible that it has a few bugs in the code.

