

# Copyright (C) 2014       Alvaro Felipe Melchor (alvaro.felipe91@gmail.com)


# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.



# This class describes the connection with the database, in this case with MongoDB. It uses to
# store everything related with pinning stuff

from pymongo import MongoClient
from config import Config

#Configuration stuff
f = file('config/config.cfg')
cfg = Config(f).config
f.close()
#


class database:

        def __init__(self,db_name,collection):
            """
            Constructor of this class
            
            Parameters: 
                -db_name: The database name 
                -collection: The collection inside our database  
            """
            connection = MongoClient(cfg.URL_DB,cfg.PORT_DB)
            self.db = connection[db_name]
            self.collection = self.db[collection]

        def get(self,id):
            """
            Return object saved with that id

            Parameters:
                -id : id that we want to return
            """
            return self.collection.find_one({ "_id" : id})

        def compare(self,canickname,hash_t):
            """
            Method to compare the hash of new certificate with one that exist.
            It's used in the validation process

            Paramaters:
                -canickname: Name of our certificate CA commonly known as ca-name
                -hash_t: Hash that we want to compare against the hash in the certificate with the ca-name provide before
            """
            value_in_db = self.get(canickname)
            if value_in_db["hash"] == hash_t:
                return True
            else:
                # This means a MITM attack because the hash changed
                return False

        def set_rfc(self,common_name):
            """
            Method to only log one certificate. The first one that was seen

            Paramaters:
                -common-name: The common-name of our certificate
            """
            data = {
                    "_id": common_name
                    }
            query_result = self.get(common_name)
            if query_result is None:
                self.collection.insert(data)
                return True
            else:
                return False


        def set_pin(self,hash_t,canickname):
            """
            Method to set a pin for a ca_nickname. Given a canickname we save in the database the pin

            Paramaters:
                -hash_t: Pin of our certificate
                -canickname: ca-name of our cerficate
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
                # That means that exist a pin for that certificate. This could be a error to try put the same certificate twice or something wrong happened.
                # Depends where this value is returned, we must be careful as it is treated
                return False

        def set_black_list(self,fingerprint_list):
            """
            Method to setup the black list database

            Parameters:
                -fingerprint_list: The list of fingerprints of each certificate
            """
            for finger in fingerprint_list:
                query = self.get(finger)
                if query is None:
                    self.collection.insert({"_id":finger})





# Only use for test
if __name__ == '__main__':
    db = database("pfc", "pinning")
    db.set_pin(8098098098, "Verisign")
    print db.get("Verisign")
    print db.compare("Verisign", 8098098098)
    print db.compare("Verisign", 80998098)
