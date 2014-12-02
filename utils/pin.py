import sys
sys.path.append("../")
from db.database import Database
from conf import config

def introduction():
  print " ** SET-UP YOUR PIN TO AUGMENT YOUR SECURITY **\n"
  print " The structure in the db is as follow: \n"
  print """ \t"_id" : "*.facebook.com",
  "issuers" : {
      "DigiCert High Assurance CA-3" : ["hash_spki in sha3_512"],
              "Other Intermediate CA" : ["hash_spki in sha3_512"]
  }"""


def merge_dict(first, second):
  """
  That function merge the second dict in the first one
  """
  for key in second:
    if key in first:
      for value in second[key]:
        first[key].append(value)
    else:
      first[key] = second[key]
  return first



if __name__ == '__main__':
  introduction()
  pin = dict()
  inp = 1
  finish = 1
  db = Database(config.DB_NAME, "pinning")
  collection = db.collection
  while inp is not 'y':
    pin["_id"] = raw_input("_id: ")
    pin["issuers"] = dict()
    while finish != 'n':
      issuer = raw_input("Issuer: ")
      pin["issuers"][issuer] = list()
      print "Put spki in the stack. If you want to quit put '0'"
      spki  = raw_input("spki of issuer: ")
      while spki != '0':
        pin["issuers"][issuer].append(spki)
        spki = raw_input("spki of issuer: ")
        if spki == '0':
          break
        pin["issuers"][issuer].append(spki)
      finish = raw_input("Do you want to continue? y/n : ")
    exist = collection.find_one({"_id" : pin["_id"]})
    if exist == None:
      collection.insert(pin)
    else:
      #We need to merge both dict
      exist = merge_dict(exist["issuers"], pin["issuers"])
      collection.update({"_id" : pin["_id"]}, exist)
    inp = raw_input("Do you want to finish? y/n : ")
    print inp
    del(pin)
    pin = dict()
    finish = 1


