class MITMNotification():

    _observers = []

    @classmethod
    def register(cls, observer):
        if observer not in cls._observers:
            cls._observers.append(observer)

    @classmethod
    def unregister(cls, observer):
        if observer in cls._observers:
            cls._observers.remove(observer)

    @classmethod
    def notify(cls, *args, **kw):
        for observer in cls._observers:
            observer.notify(*args, **kw)


class IObserver():

    """
    You must inherit this class to receive notification
    when a possible MITM happens
    """
    def notify(self, *args, **kw):
        pass

