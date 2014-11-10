from utils.iobserver import IObserver
import zope.interface
import smtplib


MESSAGE_FORMAT = "From: %s\r\nTo: %s\r\nSubject: MITM - %s\r\n\r\n%s" # %(fromAddr,to,subject,text)


class MailNotification():
    zope.interface.implements(IObserver)

    def notify(self, *args, **kw):
        fromaddr = 'alvaro.felipe91@gmail.com'
        toaddrs  = 'javi.lm.7@gmail.com'
        #msg = "You are under a MITM attack due to a fail with %s when you visited this site %s"  % (kw["title"] ,kw["message"])
        message = "It is likely that you are under a MITM attack due to a fail in the validation process when you visited %s" % kw["message"]

        msg  = MESSAGE_FORMAT % (fromaddr, toaddrs,kw["title"], message)

# Credentials (if needed)
        username = 'alvaro.felipe91@gmail.com'
        password = 'wwje tytb enxd pxny'

# The actual mail send
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.starttls()
        server.login(username,password)
        server.sendmail(fromaddr, toaddrs, msg)
        server.quit()




