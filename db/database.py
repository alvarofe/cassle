###############################################################################################
### Name: database.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares
###############################################################################################


# This class describes the connection with the database, in this case with MongoDB. It uses to
# store everything related with pinning stuff

from pymongo import MongoClient
from config import Config

#Configuration stuff
f = file('config/config.cfg')
cfg = Config(f).config
f.close()
#

#TODO add support for sslblacklist

class database:

        def __init__(self,db_name,collection):
            connection = MongoClient(cfg.URL_DB,cfg.PORT_DB)
            self.db = connection[db_name]
            self.collection = self.db[collection]

        def get(self,id):
            """
            Return object saved with that id
            """
            return self.collection.find_one({ "_id" : id})

        def compare(self,canickname,hash_t):
            """
            Method to compare the hash of new certificate with one that exist
            """
            value_in_db = self.get(canickname)
            if value_in_db["hash"] == hash_t:
                return True
            else:
                # This means a MITM attack because the hash changed
                return False

        def set_rfc(self,common_name):
            """
            Method to only log that certificate that are first seen
            """
            data = {
                    "_id": common_name
                    }
            query_result = self.collection.find_one({"_id" : common_name})
            if query_result is None:
                self.collection.insert(data)
                return True
            else:
                return False


        def set_pin(self,hash_t,canickname):
            """
            Method to set a pin for a ca_nickname
            """
            data = {
                    "_id" :  canickname,
                    "hash" : hash_t
                    }
            # but first to insert it is a good practice to see if exists other element with
            # the same id
            query_result = self.collection.find_one({"_id": canickname})
            if query_result is None:
                # We can insert it
                self.collection.insert(data)
                # This true value denotes that everything was fine
                return True
            else:
                return False

        def set_black_list(self,fingerprint_list):
            for finger in fingerprint_list:
                query = self.collection.find_one({"_id":finger})
                if query is None:
                    self.collection.insert({"_id":finger})




if __name__ == '__main__':
    db = database("pfc", "pinning")
    db.set_pin(8098098098, "Verisign")
    print db.get("Verisign")
    print db.compare("Verisign", 8098098098)
    print db.compare("Verisign", 80998098)
