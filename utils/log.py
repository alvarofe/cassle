import logging
from config import config
import os

LOGFILENAME = 'cert.log'
LOG_DIR = os.path.expanduser(config.LOG_DIR)

try:
    os.mkdir(LOG_DIR)
except OSError:
    #This error might have been arised due to the directory perhaps already exist.
    pass

LOGPATH = LOG_DIR + LOGFILENAME
logging.basicConfig(filename=LOGPATH,format='%(asctime)s -- %(levelname)s:%(message)s', level=logging.INFO)


def log_info(message="info"):
    logging.info(message)



def log_warn(message="warn"):
    logging.warning(message)


