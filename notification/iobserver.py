class IObserver():

    """
    You must inherit this class to receive notification
    when a possible MITM happens
    """
    def notify(self, *args, **kw):
        pass
