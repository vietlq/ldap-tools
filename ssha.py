#!/usr/bin/python

import sys
import hashlib
import random
import base64

################################

def gen_salt(str_len):
    salt = ""
    
    for x in range(str_len):
        salt += chr( random.randrange(0, 256) )
    
    return salt

################################

def salted_hash(the_passwd, hash_func, method_str):
    salt = gen_salt(4)
    
    hash_inst = hashlib.new(hash_func)
    hash_inst.update(the_passwd + salt)
    
    salted_hash_str = hash_inst.digest()
    salted_hash_str = salted_hash_str + salt
    salted_hash_str = base64.b64encode(salted_hash_str)
    salted_hash_str = method_str + salted_hash_str
    
    return salted_hash_str

################################

def ssha(the_passwd):
    hash_func = "sha1"
    method_str = "{SSHA}"
    
    salted_hash_str = salted_hash(the_passwd, hash_func, method_str)
    
    return salted_hash_str

################################

def smd5(the_passwd):
    hash_func = "md5"
    method_str = "{SMD5}"
    
    salted_hash_str = salted_hash(the_passwd, hash_func, method_str)
    
    return salted_hash_str

################################

def hash(the_passwd, hash_func, method_str):
    hash_inst = hashlib.new(hash_func)
    hash_inst.update(the_passwd)
    
    hash_str = hash_inst.digest()
    hash_str = base64.b64encode(hash_str)
    hash_str = method_str + hash_str
    
    return hash_str

################################

def sha(the_passwd):
    hash_func = "sha1"
    method_str = "{SHA}"
    
    hash_str = hash(the_passwd, hash_func, method_str)
    
    return hash_str

################################

def md5(the_passwd):
    hash_func = "md5"
    method_str = "{MD5}"
    
    hash_str = hash(the_passwd, hash_func, method_str)
    
    return hash_str

################################

if __name__ == "__main__":
    if len(sys.argv) == 2:
        print ssha(sys.argv[1])
        print smd5(sys.argv[1])
        print sha(sys.argv[1])
        print md5(sys.argv[1])
    else:
        print "Syntax: %s password" % sys.argv[0]

