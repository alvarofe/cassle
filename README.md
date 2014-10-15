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


#### Prerequisites
 

 
  * Python >= 2.7 (www.python.org)
  * libpcap-python - <http://sourceforge.net/projects/pylibpcap/>
  * Python binding for NSS - `$ pip install python-nss`
  * M2Crypto - `$ pip install M2Crypto`
  * pyasn1 - `$ pip install pyasn1`
  * pync - Python Wrapper for Mac OS 10.8 Notification Center - `$ pip install pync` (This is only for Mac OS X)
  * Termcolor - `$ pip install termcolor`
  * pymongo - `$ pip install pymongo` (we must have installed mongo in our computer before <http://www.mongodb.org/> )
  * python-wget `$ pip install wget`
  * config `$ pip install config`
  * apscheduler `$ pip install apscheduler`

-
Once installed all packages and before to launch the program we have to set our ROOT certificates. First we have to configure our directory to hold them. 

```bash
$ mkdir -p ~/.pki/nssdb
$ cd ~/.pki/nssdb
$ certutil -N -d .
```
I use this but whatever directory is fine. If you change the directory you have to change the config file and set `NSS_DB_DIR`. By the default is "~/.pki/nssdb". Also we have to put in the config file where are our certificates `CERTS_DIR` . This project provide the ROOT Mozilla's certificates in the certs folder. Also you should set the log directory `LOG_DIR`.

```bash
$ cd {project}
$ cd utils
$ python add_certs_to_nssdb 
```

NOTE: certutil goes wrong with der encoding so I had to convert to PEM and then install it in the nssdb. I have provided this script but if you want to write your own, feel free to do it

-
###### OPTIONAL

Also I provide a script to set pinning of our choice. These pinning won't be erased each X seconds due to they are confident for us. The rest of the pinning that we see it whilst navigate will be erased each X seconds. This number of seconds is configured in our config file `time_remove`.

```bash
$ cd {projec}/utils
$ python add_pin_to_db.py -f <folder that hold certificates>
```
-

So once we have our system ready we can execute the main program.
```bash
./sniff.py -i < interface to sniff >
```


State
=====
This project is under development and is possible that it has a few bugs in the code.

