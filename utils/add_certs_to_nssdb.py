############################################################################################### 
### Name: add_certs_to_nssdb.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares 
###############################################################################################


import optparse
import subprocess
import sys,os
from config import Config

f = file('config/config.cfg')
cfg = Config(f).config

if __name__ == '__main__':
    parser = optparse.OptionParser("usage: %prog -a <True/False>")
    parser.add_option('-a', '--add', dest='add',default=True,help='Bool indicate if add or substrate cert')
    certs = os.path.expanduser(cfg.CERTS_DIR)
    certdb = os.path.expanduser(cfg.NSS_DB_DIR)

    (opts, args) = parser.parse_args()
    if (certs == None) | (certdb == None):
        print 'Populate config file'
        sys.exit(-1)

    if opts.add == True:
        for i in os.listdir(certs):
            if os.path.isfile(os.path.join(certs,i)):
                j = i.replace('_-_',' ').replace('_',' ').strip('.crt')
                #certutil -A -n jsmith@netscape.com -t "p,p,p" -i mycert.crt -d certdir
                subprocess.call(["certutil", "-A","-n",j,'-t','C,,,','-a','-i',certs+i,
                    '-d',certdb])
    else:
        for i in os.listdir(certs):
            if os.path.isfile(os.path.join(certs,i)):
                j = i.replace('_-_',' ').replace('_',' ').strip('.crt')
                #certutil -A -n jsmith@netscape.com -t "p,p,p" -i mycert.crt -d certdir
                subprocess.call(["certutil", "-D","-n",j,'-d',certdb])
