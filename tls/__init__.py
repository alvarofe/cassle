from config import config
import nss.nss as nss
import os

#Initialize nss to work with

class NSSConfig():

    def __init__(self):
        self.certdb_dir = os.path.expanduser(config.NSS_DB_DIR)
        nss.nss_init(self.certdb_dir)
        nss.enable_ocsp_checking()
        self.certdb = nss.get_default_certdb()


nssconfig = NSSConfig()

