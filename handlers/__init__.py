class HandleStore(object):
    store = None

    def __init__(self):
        self.store= {}



def handler(store,handler=False):
    def _handler(cls):
        if handler:
            store.store[cls.name] = cls

        return cls
    return _handler


handlers = HandleStore()

from pinning import Pinning
from icsi import Icsi
from blacklist import Blacklist
from rfcnss import Rfcnss
from ocspcheck import OCSP
from ct import CT
from tlsa import TLSA

