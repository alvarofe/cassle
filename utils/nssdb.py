

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
import sys, os
sys.path.append("../")
from conf import config




if __name__ == '__main__':
  parser = optparse.OptionParser("usage: %prog -a <True/False>")
  parser.add_option('-a', '--add', dest='add', default = True, help='Bool indicate if add or substrate cert')
  certs = os.path.expanduser(config.CERTS_DIR)
  certdb = os.path.expanduser(config.NSS_DB_DIR)

  (opts, args) = parser.parse_args()
  if (certs == None) | (certdb == None):
    print 'Populate config file'
    sys.exit(-1)

  if opts.add == True:
    for i in os.listdir(certs):
      if os.path.isfile(os.path.join(certs,i)):
        j = i.replace('_-_',' ').replace('_',' ').strip('.crt')
        cmdstr = ["openssl", "x509", "-in", certs+i, "-inform", "DER", "-out", certs+i, "-outform", "PEM"]
        subprocess.call(cmdstr)
        subprocess.call(["certutil", "-A", "-n", j, '-t', 'C,,,', '-a', '-i', certs+i, '-d', certdb])
  else:
    for i in os.listdir(certs):
      if os.path.isfile(os.path.join(certs,i)):
        j = i.replace('_-_',' ').replace('_',' ').strip('.crt')
        subprocess.call(["certutil", "-D", "-n", j, '-d', certdb])
