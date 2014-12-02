import math
import base64


class Deserializer(object):

    MAX_SCT_LIST_LENGTH = (1 << 16) - 1
    MAX_SERIALIZED_SCT_LENGTH = (1 << 16) - 1

    def __init__(self, inp):
        super(Deserializer, self).__init__()
        self.current_pos_ = inp
        self.bytes_remaining_ = len(inp)

    # Returns the number of bytes needed to store a value up to max_length
    @classmethod
    def prefix_length(cls, max_length):
        return math.ceil(math.log(max_length, 2) / float(8))

    def read_fixed_bytes(self, num_bytes):
        if self.bytes_remaining_ < num_bytes:
            return False
        res = self.current_pos_[:num_bytes]
        self.current_pos_ = self.current_pos_[num_bytes:]
        self.bytes_remaining_ -= num_bytes
        return res

    def read_uint(self, num_bytes):
        if self.bytes_remaining_ < num_bytes:
            return False
        res = 0
        i = 0
        while i < num_bytes:
            res = (res << 8) | ord(self.current_pos_[0])
            self.current_pos_ = self.current_pos_[1:]
            i += 1
        self.bytes_remaining_ -= num_bytes
        return res

    def read_length_prefix(self, max_length):
        prefix_length = Deserializer.prefix_length(max_length)
        length = self.read_uint(prefix_length)
        if length is False:
            return False
        return length

    def read_var_bytes(self, max_total_length):
        # first we extract the length to read
        length = self.read_length_prefix(max_total_length)
        if length is False:
            return False

        # once we have the bytes we read it
        bytes_ = self.read_fixed_bytes(length)
        return bytes_

    def reach_end(self):
        # that is to know if we have reached the end of our buffer
        return self.bytes_remaining_ == 0


class DeserializeSCTList(Deserializer):
    def __init__(self, inp):
        super(DeserializeSCTList, self).__init__(inp)

    def read_list(self, max_total_length, max_elem_length):
        scts = list()
        bytes_scts = self.read_var_bytes(max_total_length)
        if bytes_scts is False:
            return False
        list_reader = Deserializer(bytes_scts)
        while list_reader.reach_end() is not True:
            scts.append(list_reader.read_var_bytes(max_elem_length))
        return scts

    def deserialize_list(self, max_total_length, max_elem_length):
        l = self.read_list(max_total_length, max_elem_length)
        return l

    def deserialize_sct_list(self):
        list_contain_scts = self.deserialize_list(
            self.MAX_SCT_LIST_LENGTH,
            self.MAX_SERIALIZED_SCT_LENGTH)
        return list_contain_scts


class DeserializeSCT(Deserializer):

    VERSION_LENGTH_IN_BYTES = 1
    KEY_ID_LENGTH_IN_BYTES = 32
    TIMESTAMP_LENGTH_IN_BYTES = 8
    MAX_EXTENSIONS_LENGTH = (1 << 16) - 1
    HASH_ALGORITHM_LENGTH = 1
    SIG_ALGORITHM_LENGTH = 1
    MAX_SIGNATURE_LENGTH = (1 << 16) - 1

    def __init__(self, inp):
        super(DeserializeSCT, self).__init__(inp)
        self._hash_algorithm = [None, "md5", "sha1", "sha224", "sha256",
                                "sha384", "sha512"]
        self._signature_algorithm = ["anonymous", "rsa", "dsa", "ecdsa"]

    def read_digitally_signed(self):
        hash_algo = self.read_uint(self.HASH_ALGORITHM_LENGTH)
        try:
            hash_algo = self._hash_algorithm[hash_algo]
        except:
            # Algorithm Invalid
            return False
        sig_algo = self.read_uint(self.SIG_ALGORITHM_LENGTH)
        try:
            sig_algo = self._signature_algorithm[sig_algo]
        except:
            # Signature algorithm invalid
            return False
        # sig_string = self.read_var_bytes(self.MAX_SIGNATURE_LENGTH)
        # print hash_algo
        # print sig_algo
        # print base64.b64encode(sig_string)
        pass

    def deserialize_sct(self):
        sct = SignedCertificateTimeStamp()
        version = self.read_uint(self.VERSION_LENGTH_IN_BYTES)
        sct.version = version
        logID = self.read_fixed_bytes(self.KEY_ID_LENGTH_IN_BYTES)
        sct.logID = logID
        timestamp = self.read_fixed_bytes(self.TIMESTAMP_LENGTH_IN_BYTES)
        sct.timestamp = timestamp
        extensions = self.read_var_bytes(self.MAX_EXTENSIONS_LENGTH)
        sct.extensions = extensions
        self.read_digitally_signed()
        return sct


class SignedCertificateTimeStamp(object):

    def __init__(self):
        super(SignedCertificateTimeStamp, self).__init__()
        self._version = 0
        self._logID = 0
        self._timestamp = 0
        self.extensions = None

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    @property
    def logID(self):
        return self._logID

    @logID.setter
    def logID(self, value):
        self._logID = base64.b64encode(value)

    @property
    def timestamp(self):
        aux = int(self._timestamp.encode('hex'), 16) / 1000
        return aux
        # return time.ctime(aux/1000)
        # return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        self._timestamp = value
        # aux = int(value.encode('hex'), 16)
        # self._timestamp = time.ctime(aux/1000)


