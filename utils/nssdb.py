

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
import subprocess
import sys
import os
sys.path.append("../")
from conf import config
import M2Crypto.X509
from M2Crypto.X509 import FORMAT_PEM


if __name__ == '__main__':
    parser = optparse.OptionParser("usage: %prog -a ")
    parser.add_option('--add', action='store_true', dest='add', help='Flag that indicate that you want add certificates to NSSDB')
    parser.add_option('--delete', action='store_false', dest='add',  help='Flag that indicate that you want delete certificates from NSSDB')
    certs = os.path.expanduser(config.CERTS_DIR)
    certdb = os.path.expanduser(config.NSS_DB_DIR)

    (opts, args) = parser.parse_args()
    if (certs is None) | (certdb is None):
        print 'Populate config file'
        sys.exit(-1)

    if opts.add is True:
        for i in os.listdir(certs):
            if os.path.isfile(os.path.join(certs, i)):
                file = certs+i

                #Avoid hidden files
                if i.startswith('.'):
                    continue
                # To convert to PEM encoding
                cmdstr = [
                    "openssl", "x509", "-in", certs+i, "-inform",
                    "DER", "-out", certs+i, "-outform", "PEM"]

                # Avoid some noise on the screen
                with open(os.devnull, "w") as fnull:
                    subprocess.call(cmdstr, stdout=fnull, stderr=fnull)
                cert = M2Crypto.X509.load_cert(file,format=FORMAT_PEM)
                title = cert.get_subject()
                with open(os.devnull,"w") as fnull:
                    subprocess.call(
                        ["certutil", "-A", "-n", str(title), '-t', 'C,,,', '-a', '-i', certs+i, '-d', certdb], stderr=fnull)
    else:
        for i in os.listdir(certs):
            if os.path.isfile(os.path.join(certs, i)):
                if i.startswith('.'):
                    continue
                file  = certs+i
                cert = M2Crypto.X509.load_cert(file,format=FORMAT_PEM)
                title = cert.get_subject()
                with open(os.devnull,"w") as fnull:
                    subprocess.call(["certutil", "-D", "-n", str(title), '-d', certdb], stderr=fnull)

