

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

# This class describes the connection with the database, in this case with
# MongoDB. It uses to store everything related with pinning stuff

from pymongo import MongoClient


# this class will serve as base class
class Database(object):

        def __init__(self, db_name, collection):
            """
            Constructor of this class
            Parameters:
                -db_name: The database name
                -collection: The collection inside our database

            Comment: Change the localhost and 27017 if you want change the
            location of database
            """
            super(Database, self).__init__()
            self._db_name = db_name
            self._collection = collection
            connection = MongoClient("localhost", 27017)
            self.db = connection[db_name]
            self.collection = self.db[collection]

        def get(self, id_):
            """
            Return object saved with that id

            Parameters:
                -id : id that we want to return
            """
            return self.collection.find_one({"_id": id_})


class PinDB(Database):

    def __init__(self, db_name, collection):
        super(PinDB, self).__init__(db_name, collection)

    def set_hash(self, hash_t, id_, drop=True):
            """
            Method to set a pin for a id_.

            Paramaters:
                -hash_t: Pin of our certificate
                -canickname: ca-name of our cerficate
            """
            data = {
                "_id":  id_,
                "hash": hash_t,
                "drop": drop
                }
            # but first to insert it is a good practice to see if exists other
            # element with the same id
            query_result = self.collection.find_one({"_id": id_})
            if query_result is None:
                # We can insert it
                self.collection.insert(data)
                # This value denotes that everything was fine
                return True
            else:
                # That means that exist a pin for that certificate.
                # This could be a error to try put the same certificate twice
                # or something wrong happened. Depends where this value is
                # returned, we must be careful as it is treated
                return False

    def compare(self, id_, hash_t):
            """
            Method to compare the hash of new certificate with one that exist.
            It's used in the validation process

            Paramaters:
            -id_: Identity to compare
            -hash_t: Hash that we want to compare against the hash in the
                   record saved with the id_ especified
            """
            value_in_db = self.get(id_)
            if value_in_db["hash"] == hash_t:
                return True
            else:
                # This means a MITM attack because the hash changed
                return False

    def drop_pinning(self):
            """
            Remove all the pinning whose property drop is set to True
            """
            self.collection.remove({"drop": True})


class BlackListDB(Database):

    def __init__(self, db_name, collection):
        super(BlackListDB, self).__init__(db_name, collection)

    def set_black_list(self, fingerprint_list):
            """
            Method to setup the black list database

            Parameters:
                -fingerprint_list: The list of fingerprints of each certificate
            """
            for finger in fingerprint_list:
                query = self.get(finger)
                if query is None:
                    self.collection.insert({"_id": finger})



