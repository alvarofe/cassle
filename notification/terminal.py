from notification.event_notification import IObserver


class Terminal(IObserver):

    def notify(self, *args, **kw):
        print "MITM!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

