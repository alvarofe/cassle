import ssl
import sys
import argparse
sys.path.append("../")
import M2Crypto.X509
from M2Crypto.X509 import FORMAT_PEM
import tempfile
from Crypto.Util.asn1 import DerSequence
import hashlib
import subprocess
import nss.nss as nss
from tls import nssconfig
import base64

BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"


def get_pin(server, algo):
    first_cmd = [
        'openssl', 's_client', '-connect', server+":443", '-showcerts',
        ]
    second_cmd = ['sed', '-n', "/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p"]
    p = subprocess.Popen(
        first_cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    q = subprocess.Popen(second_cmd, stdin=p.stdout, stdout=subprocess.PIPE)
    p.stdin.close()
    p.stderr.close()
    output = q.communicate()[0]
    output = output.split('-----END')
    inter = output[1]
    server = output[0]
    issuer = inter.split('CERTIFICATE-----')[2]
    cert_issuer = BEGIN + issuer + END
    cert = server + END
    x509_issuer = get_X509_from_string_pem(cert_issuer)
    x509 = get_X509_from_string_pem(cert)
    cert = nss.Certificate(x509.as_der(), nssconfig.certdb)
    spki = get_spki_from_cert(x509_issuer.as_der())
    spki_h = hash_with_algorithm_and_data(algo, spki)
    spki_b64 = base64.b64encode(spki_h)
    print "[+] PIN\n\t _id: %s" % cert.subject_common_name
    print "\t issuer : %s" % cert.issuer.common_name
    print "\t\t Base64 of SPKI with %s: %s" % (algo, spki_b64)


def get_X509_from_string_pem(data):
    with tempfile.NamedTemporaryFile(dir='/tmp', suffix='crt') as tmp:
        tmp.write(data)
        tmp.flush()
        tmp.seek(0)
        c = M2Crypto.X509.load_cert(tmp.name, FORMAT_PEM)
    return c


def hash_with_algorithm_and_data(algorithm, data):
    lib = hashlib.new(algorithm)
    lib.update(data)
    return lib.hexdigest()


def get_spki_from_cert(cert):
    cert_dec = DerSequence()
    cert_dec.decode(cert)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert_dec[0])
    spki = tbsCertificate[6]
    return spki


def get_key_from_file(file, algo):
    import os
    f = os.path.expanduser(file)
    f = os.path.abspath(f)
    x509 = M2Crypto.X509.load_cert(f, FORMAT_PEM)
    cert_der = x509.as_der()
    cert = nss.Certificate(cert_der, nssconfig.certdb)
    spki = get_spki_from_cert(cert_der)
    fingerprint = hash_with_algorithm_and_data(algo, spki)
    id = cert.subject_public_key_info.algorithm.id_str
    print "[+] KEYCONTINUITY\n\t %s of SPKI " % algo
    print "\t %s : %s " % (cert.subject_common_name, fingerprint)
    print "\t Key of type: %s" % id


def get_key(server, algorithm):

    certificate = ssl.get_server_certificate((server, 443))
    x509 = get_X509_from_string_pem(certificate)
    der_cert = x509.as_der()
    cert = nss.Certificate(der_cert, nssconfig.certdb)
    spki = get_spki_from_cert(der_cert)
    fingerprint = hash_with_algorithm_and_data(algorithm, spki)
    id = cert.subject_public_key_info.algorithm.id_str
    print "[+] KEYCONTINUITY\n\t %s of SPKI " % algorithm
    print "\t %s : %s " % (cert.subject_common_name, fingerprint)
    print "\t Key of type: %s" % id


def main(argv):
    key = False
    pin = False
    parser = argparse.ArgumentParser(description='Gather')
    parser.add_argument(
        '-s', '--server', dest="server", help="name of server")
    parser.add_argument(
        '-k', action='store_true', dest='key',
        help='Indicates that you want the key of the server')
    parser.add_argument(
        '-p', action='store_true', dest="pin",
        help='Indicate that you want extract pin')
    parser.add_argument(
        '-a', '--algorithm', dest='algo',
        help='Hash algorithm to use')
    parser.add_argument(
        '-f', '--file', dest='file', help="File to a certificate")
    parser.set_defaults(algo='sha256')
    options = parser.parse_args()
    if options.server is not None:
        server = options.server
        key = options.key
        pin = options.pin
        algo = options.algo

        if key is True:
            get_key(server, algo)
        if pin is True:
            get_pin(server, algo)
    if options.file is not None:
        get_key_from_file(options.file, options.algo)


if __name__ == "__main__":
    main(sys.argv[1:])

