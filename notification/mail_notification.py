from notification.event_notification import IObserver
import smtplib


MESSAGE_FORMAT = "From: %s\r\nTo: %s\r\nSubject: MITM - %s\r\n\r\n%s"
# %(fromAddr,to,subject,text)


class MailNotification(IObserver):

    def notify(self, *args, **kw):
        fromaddr = 'fromaddr'
        toaddrs = 'toaddrs'
        message = "It is likely that you are under a MITM attack due to a"
        + " fail in the validation process when you visited %s" % kw["message"]

        msg = MESSAGE_FORMAT % (fromaddr, toaddrs, kw["title"], message)

# Credentials (if needed)
        username = 'username'
        password = 'password'

# The actual mail send
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.starttls()
        server.login(username, password)
        server.sendmail(fromaddr, toaddrs, msg)
        server.quit()

