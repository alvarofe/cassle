############################################################################################### 
### Name: add_pin_to_db.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares 
###############################################################################################
import optparse
from db import database



if __name__ == '__main__':
    parser = optparse.OptionParser("usage: %prog -p <hash_pin> -c <ca_nickname> -c <collection_name> -d <database_name>")
    parser.add_option('-p','--pin', dest='pin',help = "Hash that pin a certificate")
    parser.add_option('-n', '--ca_nickname', dest='ca_name', help = "CA name for the hash (Attention - CA name should match the exact name that offers nss)")
    parser.add_option('-c', '--collection', dest='collection',help = "Collection name for the database")
    parser.add_option('-d', '--db_name', dest='db_name', help = "Database name")

    (opts, args) = parser.parse_args()
    if len(args) != 4:
        parser.error("Incorrect number of arguments")

    db = database(opts.db_name, opts.collection)
    db.set_pin(opts.pin, opts.ca_name)
