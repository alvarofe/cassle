import zope.interface

class IObserver(zope.interface.Interface):
    def notify(*args,**kw):
        """
        You must implement this interface to receive notification when a possible MITM
        happens
        """


