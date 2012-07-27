#!/usr/bin/env python2

"""Program to check a password against encrypted SXC files."""

from xml.etree.ElementTree import ElementTree
from Crypto.Cipher import Blowfish
import zipfile
import sys
import base64
import hashlib
import pbkdf2

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print >> sys.stderr, "Usage: %s <SXC file> <password>" % sys.argv[0]
        sys.exit(1)

    filename = sys.argv[1]
    password = sys.argv[2]
    try:
        zf = zipfile.ZipFile(filename)
    except zipfile.BadZipfile:
        print >> sys.stderr, "%s is not an StarOffice file!" % filename
        sys.exit(2)
    try:
        mf = zf.open("META-INF/manifest.xml")
    except KeyError:
        print >> sys.stderr, "%s is not an StarOffice file!" % filename
        sys.exit(3)
    #print mf.read()
    tree = ElementTree()
    tree.parse(mf)
    r = tree.getroot()
    elements = list(r.iter())
    is_encrypted = False
    key_size = 16
    for i in range(0, len(elements)):
        element = elements[i]
        if element.get("{http://openoffice.org/2001/manifest}full-path") == "content.xml":
            for j in range(i + 1, i + 1 + 3):
                element = elements[j]
                data = element.get("{http://openoffice.org/2001/manifest}checksum")
                if data:
                    is_encrypted = True
                    checksum = data
                data = element.get("{http://openoffice.org/2001/manifest}initialisation-vector")
                if data:
                    iv = data
                data = element.get("{http://openoffice.org/2001/manifest}salt")
                if data:
                    salt = data
                data = element.get("{http://openoffice.org/2001/manifest}iteration-count")
                if data:
                    iteration_count = data
                data = element.get("{http://openoffice.org/2001/manifest}algorithm-name")
                if data:
                    algorithm_name = data
                    assert(data == "Blowfish CFB")

    if not is_encrypted:
        print >> sys.stderr, "%s is not an encrypted StarOffice file!" % sys.argv[1]
        sys.exit(4)

    # print checksum, iv, salt, checksum_type, algorithm_name, iteration_count
    checksum = base64.decodestring(checksum)
    iv = base64.decodestring(iv)
    salt = base64.decodestring(salt)
    try:
        content = zf.open("content.xml").read()
    except KeyError, exc:
        print >> sys.stderr, "%s is not an encrypted StarOffice file, content.xml missing!" % sys.argv[1]
        sys.exit(5)

    original_length = len(content)

    if original_length >= 1024:
        length = 1024
        original_length = 1024

    else:
        # pad to make length multiple of 8
        pad = "00000000"
        pad_length = original_length % 8
        if pad_length > 0:
            content = content + pad[0:pad_length]
        length = len(content)

    if algorithm_name.find("Blowfish CFB") > -1:
        pwdHash = hashlib.sha1(password).digest()
        key = pbkdf2.pbkdf(pwdHash, salt, int(iteration_count), int(key_size))
        bf = Blowfish.new(key=key, mode=Blowfish.MODE_CFB, IV=iv, segment_size=64)
        pt = bf.decrypt(content[0:length])
    else:
        print >> sys.stderr, "%s uses un-supported encryption" % sys.argv[1]
        sys.exit(5)
    cchecksum = hashlib.sha1(pt[0:original_length]).digest()
    if cchecksum == checksum:
        print "Right Password!"
        sys.exit(0)
    else:
        print "Wrong Password!"
        sys.exit(7)
