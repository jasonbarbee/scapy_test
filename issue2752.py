# Copied from Scapy Issues as an example
# https://github.com/secdev/scapy/issues/2752
from scapy.all import *
from scapy.layers.tls.all import *

class ModifiedTLSClientAutomaton(TLSClientAutomaton):
    @ATMT.condition(TLSClientAutomaton.PREPARE_CLIENTFLIGHT1)
    def should_add_ClientHello(self):
        if self.client_hello:
            p = self.client_hello
        else:
            p = TLSClientHello()
        self.add_msg(p)
        raise self.ADDED_CLIENTHELLO()

# TLS Version
target_domain = "www.google.com"
version = "1.2"

ciphers = [TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]
ciphers += [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
ciphers += [TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
ciphers += [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
ciphers += [TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384]
ciphers += [TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256]
ciphers += [TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384]
ciphers += [TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
ciphers += [TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA]
ciphers += [TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA]
ciphers += [TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]
ciphers += [TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]

compression='null'
ext1 = TLS_Ext_ServerName(servernames=ServerName(servername=target_domain))
ext2 = TLS_Ext_CSR(stype='ocsp', req=OCSPStatusRequest())
ext3 = TLS_Ext_SupportedEllipticCurves(groups=['x25519', 'secp256r1', 'secp384r1'])
ext4 = TLS_Ext_SupportedPointFormat(ecpl='uncompressed')
ext5 = TLS_Ext_SignatureAlgorithms(sig_algs=['sha256+rsa', 'sha384+rsa', 'sha1+rsa', 'sha256+ecdsa', 'sha384+ecdsa', 'sha1+ecdsa', 'sha1+dsa', 'sha512+rsa', 'sha512+ecdsa'])

ext = [ext1, ext2, ext3, ext4, ext5]
ch = TLSClientHello(gmt_unix_time=10000, ciphers=ciphers, ext=ext, comp=compression)
ch.show()
t = ModifiedTLSClientAutomaton(client_hello=ch, server="www.google.com", dport=443)
t.run()