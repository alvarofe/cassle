from pync import Notifier
from notification.event_notification import IObserver


class NotificationOSX(IObserver):

    def notify(self, *args, **kw):
        """docstring for notify"""
        message_l = None
        title_l = None
        keys = kw.keys()
        if "message" in keys:
            message_l = kw["message"]
        if "title" in keys:
            title_l = kw["title"]
        Notifier.notify(message_l, title=title_l)


