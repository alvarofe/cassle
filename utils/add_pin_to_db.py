

# Copyright (C) 2014       Alvaro Felipe Melchor (alvaro.felipe91@gmail.com)


# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import optparse
import os
import nss.nss as nss
from config import config
import M2Crypto.X509
from M2Crypto.X509 import FORMAT_DER
import hashlib
import sha3
from Crypto.Util.asn1 import DerSequence
import subprocess
import sys
sys.path.append('../db')
from database import database




if __name__ == '__main__':
    parser = optparse.OptionParser("usage: %prog -f <folder with certificates> ")
    parser.add_option('-f','--folder', dest='folder',help = "Directory that holds certificates")


    (opts, args) = parser.parse_args()
    if opts.folder == None:
        parser.error("Specify the name of directory")

    path = os.path.expanduser(opts.folder)

    certdb_dir = os.path.expanduser(config.NSS_DB_DIR)
    nss.nss_init(certdb_dir)
    certdb = nss.get_default_certdb()
    db = database("pfc", "pinning")


    for i in os.listdir(path):
        file = os.path.join(path,i)
        if os.path.isfile(file):
            #f = open(file).readlines()
            #f =  ''.join(f)
            try:
                a = M2Crypto.X509.load_cert(file,format=FORMAT_DER)
            except:
                #we should transform PEM encoding to DER
                cmdstr = ["openssl", "x509","-in",file, "-inform","PEM","-out",file, "-outform","DER"]
                subprocess.call(cmdstr)
                a = M2Crypto.X509.load_cert(file,format=FORMAT_DER)

            der = a.as_der()
            cert = nss.Certificate(der,certdb)

            s = hashlib.new("sha3_512")
            cert_dec = DerSequence()
            cert_dec.decode(der)
            tbsCertificate = DerSequence()
            try:
                tbsCertificate.decode(cert_dec[0])
            except:
                continue
            try:
                spki = tbsCertificate[6]
            except:
                #FIXME observing some outcomes with the certificates given the len(tbs)-1 is spki
                #I don't know why due to spki in the rfc is in the 7th position. BTW maybe you have to 
                #research in this and adapt it based in yours certificates. Also you can develop your own script
                #but is important to use nss because the main program use serial + make_ca_nickname 
                spki = tbsCertificate[len(tbsCertificate)-1]
            s.update(spki)
            hash_t = s.hexdigest()
            serial = cert.serial_number
            _id = str(serial) + ' - ' + cert.make_ca_nickname()
            exist = db.get(_id)
            if exist == None:
                db.set_pin(hash_t,_id,drop=False)

