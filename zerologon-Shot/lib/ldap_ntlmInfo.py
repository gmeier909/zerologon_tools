import struct
import contextlib

from impacket import ntlm
from impacket.ldap import ldap
from impacket.ldap.ldapasn1 import BindRequest
from impacket.ntlm import getNTLMSSPType1

class LDAPInfo():
    def __init__(self, target, ldaps):
        self.target = target
        self.ldaps = ldaps

    def ldapinfo(self):
        try:
            ldapconnection = ldap.LDAPConnection(f'{"ldap" if not self.ldaps else "ldaps"}://{self.target}')
            bindRequest = BindRequest()
            bindRequest["version"] = 3
            bindRequest["name"] = ""
            negotiate = getNTLMSSPType1()
            bindRequest["authentication"]["sicilyNegotiate"] = negotiate.getData()
            response = ldapconnection.sendReceive(bindRequest)[0]["protocolOp"]
            ntlm_info = bytes(response["bindResponse"]["matchedDN"])
            return self.parse_challenge(ntlm_info)
        except Exception:
            return

    def parse_challenge(self, challange):
        target_info = {
            "hostname": None,
            "domain": None,
            "os_version": None
        }
        challange = ntlm.NTLMAuthChallenge(challange)
        av_pairs = ntlm.AV_PAIRS(challange["TargetInfoFields"][:challange["TargetInfoFields_len"]])
        if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME]:
            with contextlib.suppress(Exception):
                target_info["hostname"] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode("utf-16le")
        if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME]:
            with contextlib.suppress(Exception):
                target_info["domain"] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode("utf-16le")
        if "Version" in challange.fields:
            version = challange["Version"]
            if len(version) >= 4:
                major_version = version[0]
                minor_version = version[1]
                product_build = struct.unpack("<H", version[2:4])[0]
                target_info["os_version"] = f"{major_version}.{minor_version} Build {product_build}"
        return target_info