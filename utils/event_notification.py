class Singleton(object):
    _state = {}
    def __new__(cls,*args,**kw):
        ob = super(Singleton,cls).__new__(cls,*args,**kw)
        ob.__dict__ = cls._state
        return ob



class MITMNotification(Singleton):

    _observers = []
    @classmethod
    def register(cls,observer):
        if observer not in cls._observers:
            cls._observers.append(observer)

    @classmethod
    def unregister(cls,observer):
        if observer in cls._observers:
            cls._observers.remove(observer)


    @classmethod
    def notify(cls,*args,**kw):
        for observer in cls._observers:
            observer.notify(*args,**kw)
