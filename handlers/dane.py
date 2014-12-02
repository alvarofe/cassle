from handlers import handlers, handler
from handlers.base import BaseHandler
import dns.resolver
from conf import config, debug_logger
import logging



logger = logging.getLogger(__name__)

@handler(handlers, handler=config.V_TLSA)
class TLSA(BaseHandler):

  name = "tlsa"
  cert = True
  ocsp = False


  def on_certificate(self,cert):

    def verify(url):
      try:
        answer = dns.resolver.query('_443._tcp.'+ url, 'TLSA')
        answer = [str(ans) for ans in answer][0].split(' ')
        hash_tlsa = answer[len(answer) - 1]
        res = cert.hash(algorithm='sha256')
        if res == hash_tlsa:
          return True
        else:
          return False
      except:
        return False
      try:
        url = cert.subject_common_name()
      except IndexError:
        debug_logger.debug("\t[-] ERROR extracting subject_common_name")
        return
      result = False
      result = verify(url)

      if result == True:
        debug_logger.debug("\t[+] Certificate %s has a valid TLSA record" % cert.ca_name())
        return
      if url[0:3] == "www":
        url = url.replace("www.",'')
        result = verify(url)
      elif url[0] == '*':
        url = url.replace('*','www')
        result = verify(url)
      if result == True:
        debug_logger.debug("\t[+] Certificate %s has a valid TLSA record" % cert.ca_name())
        return
      debug_logger.debug("\t[-] Certificate %s has not a valid TLSA record" % cert.ca_name())

