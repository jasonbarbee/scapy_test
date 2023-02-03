# Jason Barbee jbarbee@cspire.com
# Solutions Architect / C Spire
# Testing SIP some ClientHello parameters, TLS 1.0 outer record layer, and skewing the GMT time field, which deviates from the RFC standard of current time.
import socket
from scapy.all import *
from scapy.layers.tls import *
from scapy.layers.tls.basefields import _tls_type
from datetime import *
load_layer('tls')
conf.logLevel = logging.INFO

class ModifiedTLSClientAutomaton(TLSClientAutomaton):
    # Overrides some defaults that properly adds the Hello. Otherwise... it doesn't like to send TLS 1.2 within a TLS 1.0.
    @ATMT.condition(TLSClientAutomaton.PREPARE_CLIENTFLIGHT1)
    def should_add_ClientHello(self):
        if self.client_hello:
            p = self.client_hello
        else:
            p = TLSClientHello()
        self.add_msg(p)
        raise self.ADDED_CLIENTHELLO()

    def add_record(self, is_sslv2=None, is_tls13=None, is_tls12=None):
        """
        Add a TLS Record 1.0 instead of the default override behavior.
        """
        tls = TLS(version="TLS 1.0", tls_session=self.cur_session)
        self.buffer_out.append(tls)

target_hostname = 'sip.pstnhub.microsoft.com'
target_port = 5061

current_time = datetime.now()
skewed_time = current_time.replace(year=current_time.year-5)
ext3 = TLS_Ext_SupportedEllipticCurves(groups=['secp521r1',
                                                  'secp384r1',
                                                  'secp256r1'])

ext4 = TLS_Ext_SupportedPointFormat(ecpl=[0, 1, 2])
ext5 = TLS_Ext_SignatureAlgorithms(sig_algs=[0x0601,0x0501,0x0403,0x0401,0x0201])
ext6 = TLS_Ext_EncryptThenMAC()
ext7 = TLS_Ext_ExtendedMasterSecret()
ext = [ext3, ext4, ext5, ext6, ext7]
ch = TLSClientHello(ciphers=[49200, 49196, 107, 57, 53, 49199, 49195, 103, 51, 47, 255],
                     gmt_unix_time=int(skewed_time.strftime('%s')), ext=ext)
ch.show()
t = ModifiedTLSClientAutomaton(server=target_hostname,
                       dport=target_port, client_hello=ch)
t.run()