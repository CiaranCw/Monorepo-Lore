#!/usr/bin/env python3
"""Create an isolated CA and the two server certificates. Prints no private key."""
import os, subprocess, sys
root = sys.argv[1]
ip = sys.argv[2]
os.makedirs(root, exist_ok=True)

def run(args):
    subprocess.check_call(args, cwd=root)

open(os.path.join(root, "ca.cnf"), "w").write(
    "[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n"
    "[dn]\nCN=B266-Intranet-CA\n"
    "[v3_ca]\nbasicConstraints=critical,CA:TRUE\n"
    "keyUsage=critical,keyCertSign,cRLSign\n"
    "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "ca.key", "-out", "ca.pem",
     "-days", "1825", "-nodes", "-config", "ca.cnf"])
open(os.path.join(root, "lore.ext"), "w").write(
    "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
    "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
    "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
open(os.path.join(root, "gw.ext"), "w").write(
    "subjectAltName=IP:%s,DNS:localhost\nbasicConstraints=CA:FALSE\n"
    "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
    "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" % ip)
run(["openssl", "req", "-newkey", "rsa:2048", "-keyout", "lore.key", "-out", "lore.csr", "-nodes", "-subj", "/CN=localhost"])
run(["openssl", "x509", "-req", "-in", "lore.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
     "-out", "lore.pem", "-days", "825", "-extfile", "lore.ext"])
run(["openssl", "req", "-newkey", "rsa:2048", "-keyout", "gateway.key", "-out", "gateway.csr", "-nodes", "-subj", "/CN=" + ip])
run(["openssl", "x509", "-req", "-in", "gateway.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
     "-out", "gateway.pem", "-days", "825", "-extfile", "gw.ext"])
subprocess.check_call(["openssl", "verify", "-CAfile", os.path.join(root, "ca.pem"), os.path.join(root, "lore.pem")])
subprocess.check_call(["openssl", "verify", "-CAfile", os.path.join(root, "ca.pem"), os.path.join(root, "gateway.pem")])
os.chmod(os.path.join(root, "ca.key"), 0o600)
os.chmod(os.path.join(root, "lore.key"), 0o600)
os.chmod(os.path.join(root, "gateway.key"), 0o600)
print("certs ok")
