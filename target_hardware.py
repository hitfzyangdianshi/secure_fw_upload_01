#coding=utf-8

import Crypto
from Crypto import Random
from Crypto.Hash import SHA,SHA256
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64,random
from Crypto.Cipher import PKCS1_OAEP,AES
import socket
import cPickle
import hashlib
import time,os,shutil


def apply_sha256(pw):
	m = hashlib.sha256()
	m.update(pw)
	return m.hexdigest()


def generate_nonce(length=16):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])



"""
Upon receiving a request, target hardware decrypts it using THMasterPrivKey 
and verifies message authenticity by verifying digital signature with AdminMasterPubKey, which was stored locally (2). 

"""

#cipher_text="KOKBlxACsBP8oiFwg5AmLu7zWQ8USRmOrGm+EWKVvliN7xido9qBWvheQcjqt7OHADwrPxNkblE/XcPCuSo21wLC6l7mvgAYcbjlhMqUyVcC1bb+IxexmzDh2sjFss8CqW2G6x+Y/GvF2c6a86CLA6wsbAmTSO5UJ7p9ah59eoA="

THMasterPrivKey=\
"-----BEGIN RSA PRIVATE KEY-----\n\
MIICXAIBAAKBgQDDckTwX2dc3JWFJmePbd01ymnhb4U4oEMDfDd/c+dvoaTrzCVX\n\
IInnp4OEjMFjaodFAmb2X6WfJbfzZxKhrzvg44nmC4ilGwaK6DG/cJ9peV+t7plO\n\
HC6bSOj4TK4JaejCh7yjT4FHypJPxw4njCgC/FIWtebkB4vLCvNZOWZkAwIDAQAB\n\
AoGAIQvMHjxzVJ8zZM0Gi5jO405zMpvRka5/RjKVi6ZERnq1UO02jxHAX3vSX/IQ\n\
rMeRUZjDYfrwHQWaobwWyWHApMy6WZNtXL1z868NvdGXY8jwxELKjf/MJ6k80vPb\n\
gtzg2dqMb20hpTsccreaxSxDsDPJc9mTd2hwVWSNTH9FjpkCQQDLnzYaVUwyST5q\n\
udKWhU+ZndKZ0NJiBoDJoywPcDWsf+yNhd1PWbKN+hgfK8JkXzJyF0CUTTth6L3g\n\
VA4VOr2HAkEA9bivq4wyMYUQWpjHsf2zA3v3evnbwa8+QDzOduUYsTHhhPwR/r5j\n\
bt+P7f1Ql+GpiCKt9IUNNwEm+YlMd9LkpQJBALzkSVBMaI8NmzVuhIjVym37Fm9S\n\
ZJhC6B4lnK4FrgUD9vGiiRcfYqCKrO3drktmdGmaYHIy4y+EtP/xec7/2ukCQG/1\n\
n61VasVfcM0m0c6K3xcWU/Pnhrbgh0ezrQtFZZPPO4dhZz2gOCQbnzP7+M3LV3ic\n\
/I/uU9AdKUoHwhzSrbUCQFsTLrsbm2rWovlca+TCtnyP4u75L8s3OWt3KaGuTi/z\n\
l26478qxIbj3g+Fh0xUMzED63fLX5wq/HP41opSv7Zo=\n\
-----END RSA PRIVATE KEY-----"



AdminMasterPubKey="-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDScydKll9d21yb8H0JEwaV96j/\n\
iNUp0iTgZkxPnKXEv/1xs5UahKWMwB5qH3YHkxAbhpPMzmDE2xzT8eal8NIfzwKA\n\
nk3a+EYUm6Qp8CBoOOV3pyxUo/yqsV1hvZo7B73qiwR3/8zQQlVrL+Dlrfu7Dyi2\n\
Reasm+rEPhbqc9XMWQIDAQAB\n\
-----END PUBLIC KEY-----"

# pair 1
sk = socket.socket()
ip_port=("",10086)
sk.bind(ip_port)
sk.listen(5)
print("waiting for socket data 1...")
conn, address = sk.accept()
nonce_received1 = conn.recv(16)
signature = conn.recv(172)
cipher_text = conn.recv(172) # pair 1

print "nonce_received1: ", nonce_received1
#print "signature"
#print "cipher_text"

#with open('THMasterPrivKey.pem') as f:
 #   key = f.read()
rsakey = RSA.importKey(THMasterPrivKey)
cipher = Cipher_pkcs1_v1_5.new(rsakey)
text = cipher.decrypt(base64.b64decode(cipher_text),Random.new().read)

print("socket data1 received...")


#print (text)

#nonce_received1=text#5811971567083307

#signature="Cc74TwkJREOQ1W4krh9xnrTCxNBYWjkztjRqwkToHvdf78jXSw4TdNVQ1WUrBBVKmkl/UV9+XpJF4iHMgTw6uvCCjdo9HoC8JcorKde33vxsr3CKhH8ZC0JLDd2JAItzW/SD1U5lF/Nrmc3BElCo7lDchiRd7O4qvi4yOT6rDdM="
#with open('AdminMasterPubKey.pem') as f:
  #  key = f.read()
rsakey = RSA.importKey(AdminMasterPubKey)
verifier = Signature_pkcs1_v1_5.new(rsakey)
digest = SHA.new()
    # Assumes the data is base64 encoded to begin with
digest.update(text)
signer = Signature_pkcs1_v1_5.new(rsakey)
is_verify = signer.verify(digest, base64.b64decode(signature))
   # f.close()

if is_verify== True:
    print "verify data1: ", is_verify
else :
    print("[Warning***] data1 signature is not verified...")

db_name = 'nonce_.db'
db={}

try:
    with open(db_name, 'rb') as input_db:
        db = cPickle.load(input_db)
except IOError:
    pass

nonce_hash=apply_sha256(nonce_received1)
#print "nonce_received1_hash= ",nonce_hash
nonce_timestamp=time.time()
if nonce_hash in db.keys():
    print "[Warning***] nonce1 exists at the time stamp: ", db[nonce_hash]
db[nonce_hash]=(nonce_timestamp)
with open(db_name, 'wb') as output_db:
    db = cPickle.dump(db,output_db)



# (THCurrentPrivKey and THCurrentPubKey)
"""
Target hardware generates current key pair (THCurrentPrivKey and THCurrentPubKey) 
and stores them locally, then it signs THCurrentPubKey and nonce received from admin using THMasterPrivKey, 
and then encrypts it with AdminMasterPubKey. This message is sent to the administrator (3). 
"""
###########################
rsa = RSA.generate(1024)
private_pem = rsa.exportKey()
THCurrentPrivKey=private_pem
#with open('THCurrentPrivKey.pem', 'w') as f:
#    f.write(private_pem)

public_pem = rsa.publickey().exportKey()
THCurrentPubKey=public_pem
#with open('THCurrentPubKey.pem', 'w') as f:
#    f.write(public_pem)

print("THCurrentPrivKey and THCurrentPubKey generated...")
print(THCurrentPubKey)
#THCurrentPrivKey=RSA.importKey(open("THCurrentPrivKey.pem").read())#.exportKey()
#THCurrentPubKey=RSA.importKey(open("THCurrentPubKey.pem").read())#.exportKey()
#with open("THMasterPrivKey.pem") as f:#signs THCurrentPubKey and nonce received from admin using THMasterPrivKey
   # key=f.read()
#signs THCurrentPubKey and nonce received (nonce_received1)  from admin using THMasterPrivKey
rsakey = RSA.importKey(THMasterPrivKey)
signer = Signature_pkcs1_v1_5.new(rsakey)
digest = SHA.new()
digest.update(RSA.importKey(THCurrentPubKey).exportKey())
sign = signer.sign(digest)
signature_THCurrentPubKey = base64.b64encode(sign)
digest = SHA.new()
digest.update(nonce_received1)
sign = signer.sign(digest)
signature_nonce_received1 = base64.b64encode(sign)
#f.close()

#print "signature_THCurrentPubKey: ", signature_THCurrentPubKey
#print "signature_nonce_received1: ",signature_nonce_received1

#with open("AdminMasterPubKey.pem") as f:#then encrypts it with AdminMasterPubKey
  #  key = f.read()
#then encrypts it with AdminMasterPubKey
rsakey = RSA.importKey(AdminMasterPubKey)
#AdminMasterPubKey=rsakey
#cipher = Cipher_pkcs1_v1_5.new(rsakey)
    #cipher_text1 = base64.b64encode(cipher.encrypt(signature_THCurrentPubKey))
   # cipher_text2 = base64.b64encode(cipher.encrypt(signature_nonce_received1))
   # cipher_text3 = base64.b64encode(cipher.encrypt(THCurrentPubKey))
#out_file1=open("ciphertext1signature_THCurrentPubKey", 'wb')
#out_file2 = open("ciphertext2signature_nonce_received1", 'wb')
#out_file3 = open("ciphertext3THCurrentPubKey", 'wb')
out_file1=b""
out_file2=b""
out_file3=b""
session_key=Random.get_random_bytes(16)   #一个 16 字节的会话密钥
cipher_rsa1 = PKCS1_OAEP.new(RSA.importKey(AdminMasterPubKey)) # Encrypt the session key with the public RSA key
cipher_rsa2 = PKCS1_OAEP.new(RSA.importKey(AdminMasterPubKey))  # Encrypt the session key with the public RSA key
cipher_rsa3 = PKCS1_OAEP.new(RSA.importKey(AdminMasterPubKey))  # Encrypt the session key with the public RSA key
    #cipher_rsa.encrypt(session_key)
out_file1=out_file1+cipher_rsa1.encrypt(session_key)#out_file1.write(cipher_rsa1.encrypt(session_key))
out_file2=out_file2+cipher_rsa1.encrypt(session_key)#out_file2.write(cipher_rsa2.encrypt(session_key))
out_file3=out_file3+cipher_rsa1.encrypt(session_key)#out_file3.write(cipher_rsa3.encrypt(session_key))
cipher_aes1 = AES.new(session_key, AES.MODE_EAX)  # Encrypt the data with the AES session key
ciphertext1, tag1 = cipher_aes1.encrypt_and_digest(signature_THCurrentPubKey)
cipher_aes2 = AES.new(session_key, AES.MODE_EAX)
ciphertext2, tag2 = cipher_aes2.encrypt_and_digest(signature_nonce_received1)
cipher_aes3 = AES.new(session_key, AES.MODE_EAX)
ciphertext3, tag3 = cipher_aes3.encrypt_and_digest(RSA.importKey(THCurrentPubKey).exportKey())
    #print(ciphertext1,ciphertext2,ciphertext3)
out_file1=out_file1+cipher_aes1.nonce+tag1+ciphertext1#out_file1.write(cipher_aes1.nonce)
#out_file1.write(tag1)
#out_file1.write(ciphertext1)
out_file2=out_file2+cipher_aes2.nonce+tag2+ciphertext2#out_file2.write(cipher_aes2.nonce)
#out_file2.write(tag2)
#out_file2.write(ciphertext2)
out_file3=out_file3+cipher_aes3.nonce+tag3+ciphertext3#out_file3.write(cipher_aes3.nonce)
#out_file3.write(tag3)
#out_file3.write(ciphertext3)
#out_file1.close()
#out_file2.close()
#out_file3.close()
#    f.close()

nonce2=generate_nonce()
#nonce2="2380933129441206"
print("sending socket data 2..." )
conn.send(out_file1)
conn.send(out_file2)
conn.send(out_file3)
conn.send(nonce2)
print("nonce2 sent")
print("socket data 2 sent..." )

"""
Admin decrypts received message with AdminMasterPrivKey and verifies message authenticity by decrypting digital signature with THMasterPubKey. THCurrentPublicKey is then stored locally on the admin (4). Then, admin generates current key pair (AdminCurrentPrivKey and AdminCurrentPubKey), signs AdminCurrentPubKey and nonce received from target hardware with AdminMasterPrivKey and encrypts it with THCurrentPubKey. This message is sent to the target hardware (5).


AdminMasterPrivKey= RSA.importKey(open("AdminMasterPrivKey.pem").read())
with open("ciphertext1signature_THCurrentPubKey", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(AdminMasterPrivKey.size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(AdminMasterPrivKey)
    print(AdminMasterPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data)
fobj.close()

with open("ciphertext2signature_nonce_received1", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(AdminMasterPrivKey.size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(AdminMasterPrivKey)
    print(AdminMasterPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data)
fobj.close()

with open("ciphertext3THCurrentPubKey", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(AdminMasterPrivKey.size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(AdminMasterPrivKey)
    print(AdminMasterPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data)
fobj.close()
"""


"""
Target hardware decrypts the message with THCurrentPrivKey 
and verifies message authenticity using AdminMasterPubKey (6).
"""

print("waiting for socket data3...") #pair3
fobj1=conn.recv(332)
open("ciphertext1signature_AdminCurrentPubKey", 'wb').write(fobj1)
fobj2=conn.recv(332)
open("ciphertext2signature_nonce2_received", 'wb').write(fobj2)
fobj3=conn.recv(431)
open("ciphertext3AdminCurrentPubKey", 'wb').write(fobj3)
nonce3_received=conn.recv(16)
print("socket data3 received...")


try:
    with open(db_name, 'rb') as input_db:
        db = cPickle.load(input_db)
except IOError:
    pass

nonce3_received_hash=apply_sha256(nonce3_received)
#print "nonce_received1_hash= ",nonce_hash
nonce_timestamp=time.time()
if nonce3_received_hash in db.keys():
    print "[Warning***] nonce3 exists at the time stamp: ", db[nonce3_received_hash]
db[nonce3_received_hash]=(nonce_timestamp)
with open(db_name, 'wb') as output_db:
    db = cPickle.dump(db,output_db)

#THCurrentPrivKey= RSA.importKey(open("THCurrentPrivKey.pem").read())
with open("ciphertext1signature_AdminCurrentPubKey", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(RSA.importKey(THCurrentPrivKey).size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(RSA.importKey(THCurrentPrivKey))
    #print(THCurrentPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    try:
        dataciphertext1signature_AdminCurrentPubKey = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except Exception, e:
        print (repr(e))
    else:
        print("AdminCurrentPubKey signature MAC checked...")

 #   print(dataciphertext1signature_AdminCurrentPubKey)
fobj.close()

with open("ciphertext2signature_nonce2_received", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(RSA.importKey(THCurrentPrivKey).size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(RSA.importKey(THCurrentPrivKey))
 #   print(THCurrentPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    try:
        dataciphertext2signature_nonce2_received = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except Exception, e:
        print (repr(e))
    else:
        print("nonce_received2 signature MAC checked...")
  #  print(dataciphertext2signature_nonce2_received)
fobj.close()

with open("ciphertext3AdminCurrentPubKey", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(RSA.importKey(THCurrentPrivKey).size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(RSA.importKey(THCurrentPrivKey))
   # print(THCurrentPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    try:
        dataciphertext3AdminCurrentPubKey = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except Exception,e:
        print (repr(e))
    else:
        print("AdminCurrentPubKey MAC checked...")
        print(dataciphertext3AdminCurrentPubKey)
    AdminCurrentPubKey=dataciphertext3AdminCurrentPubKey
fobj.close()

#and verifies message authenticity using AdminMasterPubKey (6).
#with open('AdminMasterPubKey.pem') as f:#and verifies message authenticity using AdminMasterPubKey (6).
  #  key = f.read()
rsakey = RSA.importKey(AdminMasterPubKey)
verifier = Signature_pkcs1_v1_5.new(rsakey)
digest = SHA.new()
    # Assumes the data is base64 encoded to begin with
digest.update(dataciphertext3AdminCurrentPubKey)
signer = Signature_pkcs1_v1_5.new(rsakey)
is_verify = signer.verify(digest, base64.b64decode(dataciphertext1signature_AdminCurrentPubKey))
#    f.close()

if is_verify== True:
    print "verify signature_AdminCurrentPubKey ", is_verify
else :
    print("[Warning***] signature_AdminCurrentPubKey is not verified...")


#with open('AdminMasterPubKey.pem') as f:
  #  key = f.read()
rsakey = RSA.importKey(AdminMasterPubKey)
verifier = Signature_pkcs1_v1_5.new(rsakey)
digest = SHA.new()
    # Assumes the data is base64 encoded to begin with
digest.update(nonce2)
signer = Signature_pkcs1_v1_5.new(rsakey)
is_verify = signer.verify(digest, base64.b64decode(dataciphertext2signature_nonce2_received))
 #   f.close()
if is_verify== True:
    print "verify signature_nonce2_received ", is_verify
else :
    print("[Warning***] signature_nonce2_received is not verified...")

######################################################################################

print("receiving socket data4 (fw pack) ...")


try:
    with open('a.zip','wb') as f:
        while True:
            data = conn.recv(1024)
            if data == b'quit':
                conn.send("quit".encode())
                break
            #写入文件
   #         print(data)
            f.write(data)
            if data[-4:] == b'quit':
                conn.send("quit".encode())
                break
        #    #接受完成标志
        #   conn.send('success'.encode())
except socket.error:
    conn.close()

print("socket data4 (fw pack) received...")

conn.close()

import zipfile
zfile = zipfile.ZipFile('a.zip','r')
zfile.extractall(path="a/")

"""
To start decryption process, session key has to be decrypted with THCurrentPrivKey (1). 
"""


with open("a/encrypted_fw.file", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(RSA.importKey(THCurrentPrivKey).size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(RSA.importKey(THCurrentPrivKey))
   # print(THCurrentPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    try:
        datafw = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except Exception, e:
        print (repr(e))
    else:
        print("fw MAC checked...")
   # open("test.img","wb").write(datafw)
fobj.close()

with open("a/encrypted_fwsignature", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(RSA.importKey(THCurrentPrivKey).size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(RSA.importKey(THCurrentPrivKey))
   # print(THCurrentPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    try:
        datafwhash = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except Exception,e:
        print (repr(e))
    else:
        print("fw signature MAC checked...")
  #  print(datafwhash)
fobj.close()

with open("a/encrypted_noncesignature", 'rb') as fobj:
  #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
    enc_session_key=fobj.read(RSA.importKey(THCurrentPrivKey).size_in_bytes())
    NONCE=fobj.read(16)
    tag=fobj.read(16)
    ciphertext =  fobj.read(-1)
    cipher_rsa = PKCS1_OAEP.new(RSA.importKey(THCurrentPrivKey))
   # print(THCurrentPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
    try:
        datasignature_nonce3 = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except Exception, e:
        print (repr(e))
    else:
        print("nonce3 signature MAC checked...")
  #  print(datasignature_nonce3)
fobj.close()

#nonce3_received="1349095738285700"#5de96242a5dcd591fe325aa713c142c2011ea0c69487030526505559fef7e347
print "nonce3_received: ", nonce3_received

#with open('../AdminCurrentPubKey.pem') as f:
   # key = f.read()
rsakey = RSA.importKey(AdminCurrentPubKey)
verifier = Signature_pkcs1_v1_5.new(rsakey)
digest = SHA.new()
    # Assumes the data is base64 encoded to begin with
h_nonce3 = SHA256.new()
h_nonce3.update(nonce3_received)
digest.update(h_nonce3.hexdigest())
signer = Signature_pkcs1_v1_5.new(rsakey)
is_verify = signer.verify(digest, base64.b64decode(datasignature_nonce3))
  #  f.close()
if is_verify == True:
    print "verify signature_nonce3_received", is_verify
else:
    print("[Warning***] signature_nonce3_received is not verified...")
#print (is_verify)

#with open('../AdminCurrentPubKey.pem') as f:
  #  key = f.read()
rsakey = RSA.importKey(AdminCurrentPubKey)
verifier = Signature_pkcs1_v1_5.new(rsakey)
digest = SHA.new()
    # Assumes the data is base64 encoded to begin with
h_fw = SHA256.new()
h_fw.update(datafw)
digest.update(h_fw.hexdigest())
signer = Signature_pkcs1_v1_5.new(rsakey)
is_verify = signer.verify(digest, base64.b64decode(datafwhash))
  #  f.close()
if is_verify == True:
    print "verify singnature hash_fw", is_verify
else:
    print("[Warning***] singnature hash_fw is not verified...")
#print (is_verify)

if(is_verify==True):
    with open("a/encrypted_fw.file", 'rb') as fobj:
        #  enc_session_key, NONCE, tag, ciphertext = [fobj.read(x) for x in (AdminMasterPrivKey.size_in_bytes(),  16, 16, -1)]
        enc_session_key = fobj.read(RSA.importKey(THCurrentPrivKey).size_in_bytes())
        NONCE = fobj.read(16)
        tag = fobj.read(16)
        ciphertext = fobj.read(-1)
        cipher_rsa = PKCS1_OAEP.new(RSA.importKey(THCurrentPrivKey))
        # print(THCurrentPrivKey.size_in_bytes(),enc_session_key,NONCE,tag,ciphertext)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, NONCE)
        datafw = cipher_aes.decrypt_and_verify(ciphertext, tag)
    open("fw_final.img","wb").write(datafw)
    fobj.close()
    #SHA256 Hash#  4aa6705efd8e0bbe72899411182e2cd1b075ecc1cc0a36a9e052c1fb312f3ba0
    print("done")

print "\n\nhash_fw: \n",h_fw.hexdigest()
print(apply_sha256(open("fw_final.img","rb").read()))

os.remove("ciphertext1signature_AdminCurrentPubKey")
os.remove("ciphertext2signature_nonce2_received")
os.remove("ciphertext3AdminCurrentPubKey")
os.remove("a.zip")
shutil.rmtree("a")

#python -m nuitka main_th.py
