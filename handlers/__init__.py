class HandleStore(object):
    """
    HandleStore will save each handler to validate the certificate
    """
    store = None

    def __init__(self):
        self.store = {}


def handler(store, isHandler=False):
    """
    decorator to set up our class as verification-class
    """
    def _handler(cls):
        if isHandler:
            store.store[cls.name] = cls
        return cls
    return _handler


handlers = HandleStore()

from keycontinuity import KeyContinuity
from icsi import Icsi
from blacklist import Blacklist
from rfcnss import Rfcnss
from ocspcheck import OCSP
from ct import CT
from dane import Dane
from pin import Pinning
#from pruebas import Prueba


