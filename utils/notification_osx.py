from pync import Notifier
from utils.iobserver import IObserver
import zope.interface



class NotificationOSX():

    zope.interface.implements(IObserver)

    def notify(self,*args,**kw):
        """docstring for notify"""
        message_l = None
        title_l = None
        keys = kw.keys()
        if "message" in keys:
            message_l = kw["message"]
        if "title" in keys:
            title_l = kw["title"]
        Notifier.notify(title_l,title=message_l)


