

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
