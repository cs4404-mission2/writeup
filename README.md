# CS4404 Mission 2(FA)
Jake Ellington and Nate Sales

# Reconnaissance
## SMS

### Overview

SMS 2FA is typically implemented where a provider sends a randomly generated, short lived numerical pin over SMS to a user's device. The user then enters this code into the website to prove that they are in possession of the cellular device. Like other 2FA designs, the goal of SMS is to provide another layer of authentication for a user.

### Failures

The most significant problem with this design is that SMS isn't encrypted in transport. An on-path adversary is able to intercept the pin over the air or over the telco's backend infrastructure, typically involving a routing protocol like SS7 [1].

An alternate means of compromise is SIM swapping - where an attacker convinces the phone company to reroute a victim's texts and calls to a phone under the attacker's control [2]. SIM swapping is not just a hypothetical attack but has been used recently in major cryptocurrency thefts such as the theft of $24 Million in bitcoin [3]. This attack involves re-assigning a phone number from one SIM card to another. This can be done either by social engineering telco employees, bribing them, or simply stealing the tablet out of the hands of a telco store manager. This is a significant issue as the attack is relatively low skill and is a vulnerability at the transport level. The flaws with SMS 2FA cannot be addressed by the authenticating party other than simply not using it. These transport-level vulnerabilities also apply to telephony-based authentication systems.

### Successes

The primary advantage to SMS 2FA is that it "just works."  Other authentication mechanisms require a user to install an application on their smart phone which may be incompatible or require the user to purchase a hardware token which can be cost-prohibitive, especially at scale. However, SMS is an old, well tested, and extremely widespread protocol. No matter what hardware you have, SMS will probably work and is not difficult for technically illiterate users to set up. In this sense, SMS is successful because it is still much better than nothing. Security practices are only effective if people actually use them after all. SMS does also have the advantage that an attack consisting of simply bombarding the user with authentication requests is less likely to work as the right code must be matched with the right request.

[1] https://usa.kaspersky.com/blog/ss7-hacked/17099/

[2] https://blog.mozilla.org/en/internet-culture/mozilla-explains/mozilla-explains-sim-swapping/

[3] https://markets.businessinsider.com/currencies/news/bitcoin-investor-loses-24-million-of-crypto-sim-swap-hackers-2019-11-1028677818

## FIDO

### Overview

FIDO2 is an authentication mechanism that uses asymmetric key signing. When a FIDO2 device is added as an MFA method to a website, the website stores the device's public key. Subsequently when the user logs in, the website sends a challenge to the device, which signs the challenge with its private key and sends the signed message back to be verified with the public key. 

The security goal of this factor is authenticity. It proves that the person attempting to access the account has a FIDO2 device with a private key that corresponds to the public key that the server knows. This method assumes that the server generates unique challenges, that the FIDO2 key does not divulge its private key, and that the hardware token can be trusted.

### Failures
A notable failure of a FIDO2 device was the audit of the NitroKey FIDO USB token including the disclosure of CVE-2020-12061 which scored 9.8. This CVE was one of many issues discovered in a security assessment by cure53. This included hardware flaws such as oboard components communicating in the plane allowing an attacker to steal any secrets stored in the device and manipulate its firmware if they had physical access. Of course this is not an attack that can be done easily or on a large scale, but running arbitrary code on a security device is a major issue. Additionally, the firmware had other issues that allowed an attacker to bypass password protection to generate OTP codes. Additionally, the microcontroller's security bit was unset by default, allowing an attacker to overwrite program code on the device. These exploits would allow an attacker to use the device to generate authentication codes without user approval or steal the FIDO2 private key and effectivley make a clone of the device. 

### Successes

While the NitroKey failures do significantly decrease security against a targeted, high skill attacker, it was still secure to the vast majority of attacks. An attacker would need either physical access to the key or remove access to the user's computer with the key connected. The far more likely threat vector of mass credential stuffing from a remote attacker would not be able to access the account as the FIDO2 protocol was not broken, only the physical hardware had issues. Other hardware tokens like the YubiKey have seen widespread usage and success.

## Prompt Authentication

### Overview

Multiple providers, namely Google and Microsoft, offer app-based authentication. When a user logs in to an untrusted device, they are prompted to "tap yes on {PHONE NAME} to approve sign in." When the user presses yes in the app, it communicates with the provider's servers and allows the sign in. Google has a variant of this system which displays a number on the machine trying to log in and several numbers on the authenticating phone. The user must tap the correct number to allow the sign in. 

### Failures

One issue with this system is that of availability. Unlike TOTP based authentication apps, prompt-based apps require the user's phone to have a stable network connection. Additionally unlike SMS, they require that the user's phone be running an up to date mainstream mobile operating system (Android or iOS). This raises issues of availability and convenience which may drive users to simply turn 2FA off. 

The major issue with prompt based authentication, specifically the Yes/No variant, is prompt spamming. This is when an attacker sends repeated requests for authentication to a user's device and hopes that one of the times they slip up and accidentally approve the request. Notably, this was used to compromise some Twitter employee accounts in 2020. 

### Successes

While prompt spamming is an issue for prompt authentication, there are already mitigations for this attack such as Google's number-based prompt. Additionally, these prompts are often secured by the phone's on-board security such as Face ID authentication to approve Microsoft Authenticator requests, whereas SMS or phone calls can often be read when the device is locked. Finally, this system is not vulnerable to the transport vulnerabilities plaguing SMS and telephony as all communications between the app and server are TLS encrypted. This authentication method offers ease of use for most users, no cost overhead, and better security than SMS not including human error. 

# Infrastructure
The infrastructure for this project consists of a web server, an automated VOIP system that dials users and prompts for authentication, and corresponding VOIP infrastructure to allow the calls to be placed. All servers were hosted on a private cluster with public IP addresses due to difficulties with accessing the class VMs through GlobalProtect (it throws SSL errors or won't install  on Linux). 

## Webserver
The webserver for this project is a modified version of the voting server from mission 1. It is a Rust binary built with the Rocket API with an sqlite database to keep track of user data and credentials. Anonymity is not a security goal of this system, user authorization is verified with an encrypted cookie whose content is the user's username and a flag indicating whether or not the user has authenticated via phone. This cannot be faked by the client as the cookie is signed and encrypted with a key known only to the server. 

When A user logs in to the webserver, it hashes their password with Argon2 and compares it with the user's record in the database. If these match, the user is given the aforementioned cookie with the MFA flag set to zero. For example, the user `jmellington`'s cookie's decrypted value would be `jmellington0`. The client browser is then redirected to the content page that checks for the authorization cookie when the page is loaded. If the cookie is not present or invalid, the user gets sent back to the login page. If the cookie is present but the MFA flag is unset, the database is queried to see if the user did complete MFA since the last check and updates the flag accordingly. If the user has not, the webpage issues a server-side GET authorization request from the autodialer's API endpoint containing the client's phone number. This is similar in structure to SSO. If the user did complete MFA, the autodialer makes a POST to an endpoint on the webserver, the user's token is re-issued with the MFA flag set, and the homepage will display its content. 

## Autodialer
The Autodialer is a python program build with flask for the API endpoint and pyvoip for VOIP operations. When it receives an authorization request over http it places a call to the user's phone number, it plays a pre-recorded message instructing the user to press pound to authorize their login and waits. If it detects the Dial Tone Multi Frequency (DTMF) code (941Hz and 1477Hz) for the pound key, it sends a POST to the webserver that the phone number was authorized successfully. If no such code is detected after 16 seconds, it notifies the server that the authorization was not successful and hangs up. In this configuration, the autodialer service is hosted on the same VM as the webserver (VM 1). As such, the API endpoint only listens on the localhost `127.0.0.1` interface, protecting it from outside manipulation. 

## PBX
The PBX that the autodialer and target's softphone hook into is a locally hosted asterisk PXB.

## Client

The client / target softphone is a the Gnome Phone VOIP client running on one of our laptops, configured to use extension 20 on the PBX and is attatched to the virtual network via an SSH proxy. 


# Attack
## Reconnaissance

### Webserver
The first step in exploiting a web service is to explore the developer tools while interacting with it. We first logged in as normal and analyzed the authentication cookie it gave us. We noticed that it changed when we successfully authenticated with MFA but that the cookie value was completely different across different sessions for the same user, so a replay would not be possible. This is due to the server's use of NONCE values when encrypting and signing the cookies.

Not being able to attack cookies, we looked at the network section of the developer tools and noticed that in most cases, the website only made a single GET or POST to the webserver, as expected. However, during two factor authentication, it makes another GET to an external resource before the content is loaded. This GET turned out to be a goldmine as it gave us two critical pieces of information: the first was that authentication is handled by the server at the address `REPLACEME`. The second piece of information was that this GET leaked the full phone number of the user. As shown in the figure below, the webpage usually censors the phone number in the format `(***)-***-XXXX`, however the GET contained the full phone number of the user for 2FA. Now we know both the client and server responsible for the authentication process.

### VOIP

The next step was to see how SIP and RTP packets were handled on the network. To do this, we logged in as a legitimate user and installed scapy and a softphone on a laptop on the network. We then initiated the authentication process and used the `sniff()` function to capture the traffic. Sample RTP and SIP packets are shown below:

```python
RTP:
<Ether  dst=e2:08:0d:bf:31:82 src=72:fe:16:95:d3:0e type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=120 id=9903 flags=DF frag=0 ttl=51 proto=udp chksum=0x5769 src=130.215.126.203 dst=XX.XX.XX.XX |<UDP  sport=49094 dport=13418 len=100 chksum=0x3ccc |<Raw  load='\x80\x00\x0b%G\xc0V\x1d%C\xe0\xb0\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb2\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb2\xb1\xb1\xb1\xb1\xb1\xb1\xb1\xb2\xb2\xb2\xb2\xb2\xb2\xb1\xb2' |>>>>
```

```python
SIP:
<Ether  dst=e2:08:0d:bf:31:82 src=72:fe:16:95:d3:0e type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=592 id=19185 flags=DF frag=0 ttl=35 proto=udp chksum=0x6c34 src=20.203.193.242 dst=XX.XX.XX.XX |<UDP  sport=5155 dport=sip len=572 chksum=0x5698 |<Raw  load='REGISTER sip:XX.XX.XX.XX SIP/2.0\r\nVia: SIP/2.0/UDP 10.5.0.4:5155;branch=z9hG4bK-3073724805;rport\r\nContent-Length: 0\r\nFrom: "2222" <sip:2222@XX.XX.XX.XX>;tag=323232323a436c61726f4e4f4301333936383734323032\r\nAccept: application/sdp\r\nUser-Agent: FPBX\r\nTo: "2222" <sip:2222@XX.XX.XX.XX>\r\nContact: sip:XXX@XX.XX.XX.XX\r\nCSeq: 2 REGISTER\r\nCall-ID: XXXXXXXX\r\nMax-Forwards: 70\r\nAuthorization: Digest username="XXXX",realm="asterisk",nonce="XXXX",uri="sip:XX.XX.XX.XX",response="bf06c829a2b5cbb9ec797be8ff4ce046",algorithm=MD5\r\n\r\n' |>>>>
```

Sensitive data such as some IP addresses have been replaced with `XX`. 

Both communication types are identified as a raw UDP payload, however they are easily differentiable due to the different ports used and the fact that the RTP data is raw bytes. 

## Setting up virtual interfaces
todo: talk about adding another nic on a vlan for communications with the pbx

## Admiral Crunch
Now that BGP manipulation has put us in-path between the authentication system's PBX and the target's phone, we have to actually manipulate the pertinent traffic to allow the login without being detected. To sniff and manipulate traffic, we are using Scapy which is a CLI utility and python library that allows for packet capture and generation. To capture packets, we use Scapy's `bridge_and_sniff` function which allows us to forward traffic from one interface to the other while inspecting and tampering with any traffic flowing through. In our configuration, `enp5s0` was facing the PBX and `enp5s1` was facing outward. This is set up in the second to last line in the program: 

```python
packetlog = scapy.sendrecv.bridge_and_sniff(if1='enp5s0',if2='enp5s1',xfrm12=gatekeep, xfrm21=keepgate)`. 
```

The `xfrmXX` arguments are functions that are called for every packet moving from if1 to if2 or vice versa. We'll first look at gatekeep, the function responsible for handling PBX to client communication. It first checks if the packet is related to VOIP and if it isn't automatically forwards it with no modification. 

```python
if not pkt.haslayer("UDP"): 
    return True
```

Scapy automatically classifies packets by their payloads and a captured packet includes all layers from the Ethernet frame to the application specific protocol. However, it does not have support for the SIP protocol which is responsible for establishing VOIP calls, hence the 'Raw' packet type. If last layer of the packet is Raw and destined for port 5060, we assume it's SIP and parse it as such. If the packet is an INVITE, we grab the to and from extensions which allows us to associate a phone number to an IP address and create a new `conversation` object. If the packet is a BYE, we discard the conversation object. Otherwise, just allow it through. 

If the call originates from the authentication server's extension, the call automatically enters "enforcing" mode after 1.5 seconds. If an RTP packet comes from the PBX whose conversation is in enforcing mode, it's original payload is removed and replaced with innocuous audio before then being forwarded. This ensures that the user does not become suspicious when the system gives the response "authentication successful" when they authorized no such authentication.
When the conversation goes into enforcing mode, the `keepgate` function which is controlling traffic from clients to the PBX, starts manipulating RTP data. Using the same process as above, it injects the DTMF code for "#" into the call by replacing audio packets originating from the user. The function to replace the packets is as follows:

```python
def manipulate(self, pkt: Packet):
    content = self.txbuff.read(160)
    #try to read 1 packet worth of data from audio buffer
    #if we don't have enough for a full packet, just let the OG packet through
    if len(content) < 160:
        logging.info("Done with DTMF transmission")
        return pkt
    # Encode payload for PCMU transmission
    content = audioop.bias(content, 1, -128)
    content = audioop.lin2ulaw(content, 1)
    # Replace payload with DTMF code
    pkt.lastlayer().remove_payload()
    pkt.lastlayer().add_payload(content)
    return pkt
```
This approves the authentication without the user's interaction (other than picking up the phone) or knowledge.

# Defense
## Telephony
There are a number of defenses which would add complexity to the attack and make it harder to compromise, however none of them could truly prevent an attack of this nature. For example, one defense would be rather than the user just pressing pound, display a code on the website that they must enter into the phone, (this could also be done the other way around). While this would require more complexity on the part of the man in the middle software, the attacker still has access to the website and the phone call so they can still forge authentication. In fact, a system where a code is read over the phone and entered on the website only requires the attacker to be on-path rather than in-path. Due to the nature of telephony and the transport layer vulnerabilities, automated calls will never be an infallible second factor. A low skill attacker can just steal the phone as most phones allow a user to answer a call without unlocking the device by default. A mid-tier attacker could social engineer a telco employee and SIM swap. A hypothetical state actor such as the Not-real Shueworld Adversary (NSA for short) may already have equipment in-path in collaboration with the service provider. Due to these factors and the lack of cryptography by default, this method is simply too insecure against a motivated, targeted adversary.

While the best defense is to prevent an attacker from getting on-path via BGP security, this cannot be done by a website and must be done by service providers. What websites could do is offer better authentication methods such as TOTP and FIDO2. And, critically, not allow telephony as a fallback if the user cannot authenticate by the more secure means. A chain is only as strong as its weakest link. 
