#!/usr/bin/python

"""
http://www.python-ldap.org/doc/html/index.html
"""

import sys
import re
import ldap
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

def hash_plain_passwd():
	hashed_pass_regex = '^\{(MD5|SHA|SMD5|SSHA|CRYPT)\}'
	
	ldap_inst = ldap.initialize('ldap://localhost')
	ldap_inst.simple_bind_s('dc=example,dc=com', 'LDAP_ROOT_PASSWORD')
	
	#found = ldap_inst.search_s('ou=people,dc=example,dc=com', ldap.SCOPE_SUBTREE, '(uid=*@*)', ['dn', 'cn', 'mail', 'sn', 'uid', 'userPassword', 'objectClass', 'givenName'])
	#found = ldap_inst.search_s('ou=people,dc=example,dc=com', ldap.SCOPE_SUBTREE, '(uid=*@*)')
	#found = ldap_inst.search_s('ou=people,dc=example,dc=com', ldap.SCOPE_SUBTREE, '(uid=vietlq@*)')
	found = ldap_inst.search_s('ou=people,dc=example,dc=com', ldap.SCOPE_SUBTREE, '(objectClass=inetOrgPerson)', ['userPassword'])
	
	count = 0
	hashed_count = 0
	unhashed_count = 0
	for entry in found:
		count += 1
		dn = entry[0]
		userPassword = entry[1]['userPassword']
		print "count = %s\ndn: %s\nuserPassword: %s" % (count, dn, userPassword)
		
		if len(userPassword):
			userPassword = userPassword[0]
		else:
			userPassword = ""
		userPassword = userPassword.strip(" \t")
		
		matches = re.search(hashed_pass_regex, userPassword, flags=re.IGNORECASE)
		
		if matches:
			print "Password is hashed!\n"
			hashed_count += 1
		else:
			print "Password must be hashed!"
			unhashed_count += 1
			ldap_inst.passwd_s(dn, userPassword, ssha(userPassword))
			print "Converted plain password to SSHA!\n"
	
	print "Total hashed passwords: %s" % hashed_count
	print "Total unhashed passwords: %s" % unhashed_count

################################################################

if __name__ == "__main__":
	hash_plain_passwd()
