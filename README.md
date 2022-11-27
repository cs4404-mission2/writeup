# CS4404 Mission 2(FA)
Jake Ellington and Nate Sales

# Reconnaissance
## SMS

SMS 2FA is typically implemented where a provider sends a numerical pin over SMS to a user's device. Like other 2FA designs, the goal of SMS is to provide another layer of authentication for a user.

The most significant problem with this design is that SMS isn't encrypted in transport. An on-path adversary is able to intercept the pin over the air or over the telco's backend infrastructure, typically involving a routing protocol like SS7 [1].

An alternate means of compromise is SIM swapping - where an attacker convinces the phone company to reroute a victim's texts and calls to a phone under the attacker's control [2].

[1] https://usa.kaspersky.com/blog/ss7-hacked/17099/

[2] https://blog.mozilla.org/en/internet-culture/mozilla-explains/mozilla-explains-sim-swapping/


## FIDO
FIDO2 is an authentication mechanism that uses asymmetric key signing. When a FIDO2 device is added as an MFA method to a website, the website stores the device's public key. Subsequently when the user logs in, the website sends a challenge to the device, which signs the challenge with its private key and sends the signed message back to be verified with the public key. 

The security goal of this factor is authenticity. It proves that the person attempting to access the account has a FIDO2 device with a private key that corresponds to the public key that the server knows. This method assumes that the server generates unique challenges, that the FIDO2 key does not divulge its private key, and that the hardware token can be trusted.

### Failures
A notable failure of a FIDO2 device was the audit of the NitroKey FIDO USB token including the disclosure of CVE-2020-12061 which scored 9.8. 


## Telephone

# Infrastructure
The infrastructure for this project consists of a web server, an automated VOIP system that dials users and prompts for authentication, and corresponding VOIP infrastructure to allow the calls to be placed.

## Webserver
The webserver for this project is a modified version of the voting server from mission 1. It is a Rust binary built with the Rocket API with an sqlite database to keep track of user data and credentials. Anonymity is not a security goal of this system, user authorization is verified with an encrypted cookie whose content is the user's username and a flag indicating whether or not the user has authenticated via phone. This cannot be faked by the client as the cookie is signed and encrypted with a key known only to the server. 

When A user logs in to the webserver, it hashes their password with Argon2 and compares it with the user's record in the database. If these match, the user is given the aforementioned cookie with the MFA flag set to zero. For example, the user `jmellington`'s cookie's decrypted value would be `jmellington0`. The client browser is then redirected to the content page that checks for the authorization cookie when the page is loaded. If the cookie is not present or invalid, the user gets sent back to the login page. If the cookie is present but the MFA flag is unset, the database is queried to see if the user did complete MFA since the last check and updates the flag accordingly. If the user has not, the webpage issues a client-side GET authorization request from the autodialer's API endpoint containing the client's phone number. This is similar in structure to SSO. If the user did complete MFA, the autodialer makes a POST to an endpoint on the webserver, the user's token is re-issued with the MFA flag set, and the homepage will display its content. 

## Autodialer
The Autodialer is a python program build with flask for the API endpoint and pyvoip for VOIP operations. When it receives an authorization request over http it places a call to the user's phone number, plays a pre-recorded message instructing the user to press pound to authorize their login and waits. If it detects the Dial Tone Multi Frequency (DTMF) code (941Hz and 1477Hz) for the pound key, it sends a POST to the webserver that the phone number was authorized successfully. If no such code is detected after 16 seconds, it notifies the server that the authorization was not successful and hangs up. In this configuration, the autodialer service is hosted on the same VM as the webserver (VM 1). 

## PBX
The PBX that the autodialer and target's softphone hook into is a locally hosted asterisk PXB.


# Attack
## Reconnaissance

### Webserver
The first step in exploiting a web service is to explore the developer tools while interacting with it. We first logged in as normal and analyzed the authentication cookie it gave us. We noticed that it changed when we successfully authenticated with MFA but that the cookie value was completely different across different sessions for the same user, so a replay would not be possible. This is due to the server's use of NONCE values when encrypting and signing the cookies.

Not being able to attack cookies, we looked at the network section of the developer tools and noticed that in most cases, the website only made a single GET or POST to the webserver, as expected. However, during two factor authentication, it makes another GET to an external resource before the content is loaded. This GET turned out to be a goldmine as it gave us two critical pieces of information: the first was that authentication is handled by the server at the address `REPLACEME`. The second piece of information was that this GET leaked the full phone number of the user. As shown in the figure below, the webpage usually censors the phone number in the format `(***)-***-XXXX`, however the GET contained the full phone number of the user for 2FA. Now we know both the client and server responsible for the authentication process.

## Setting up virtual interfaces
todo: talk about adding another nic on a vlan for communications with the pbx

## Admiral Crunch
Now that we're in-path for communications to and from the PBX, we need to actually manipulate the call. To do this, we used the Scapy packet manipulation program. Scapy is a command-line utility and python library that allows packet capture, analysis, and generation. For our purposes, we wrote Admiral Crunch, a python program that makes use of the Scapy library so the attack is fully automated. We use Scapy's `bridge_and_sniff` function which bridges our two interfaces, automatically forwarding all packets to and from the PBX. However the function's `xfrm12` argument allows us to specify a function which can prevent the packet from being forwarded or modify the packet before forwarding.

This gatekeeping function checks each packet to see if it is an SIP or RTP packet. If it is, it adds it to a conversation object which contains the conversation's to and from IP address, an `enforce` flag, and an audio buffer. SIP packets are parsed to check if the call has ended. RTP packets are converted into an audio stream and written to the conversation's buffer. If the enforce flag is set in the conversation, the packet's original content is stripped and replaced with the DTMF "#" code before being forwarded. Otherwise, it is forwarded as-is. By replacing only the RTP payload of the packet but leaving all other layers and the RTP header intact, instead of simply injecting new packets, the system does not have to contend with modifying sequence numbers or timestamps as they were legitimately generated by the user's phone.  

A separate thread iterates through each conversation and runs the audio buffer through on-device speech recognition. If the recognition system detects certain keywords such as "authentication" or "press pound", it will set the conversation's enforcing flag to true. 

Admiral Crunch's manipulation function is called by the gatekeeper `xfrm12` function and reads as follows:

```python
def manipulate(self, pkt: Packet):
        content = self.txbuff.read(160)
        #try to read 1 packet worth of data
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
*Note: The `txbuff` referenced above is a buffer of 0.25 seconds of the DTMF "#" code audio*

# Defense
## Telephony
There are a number of defenses which would add complexity to the attack and make it harder to compromise, however none of them could truly prevent an attack of this nature. For example, one defense we implemented was that, rather than the user just pressing pound, display a code on the website that they must enter into the phone, (this could also be done the other way around). While this would require more complexity on the part of the man in the middle software, the attacker still has access to the website and the phone call so they can still forge authentication. In fact, a system where a code is read over the phone and entered on the website only requires the attacker to be on-path rather than in-path. Due to the nature of telephony, automated calls will never be an infallible second factor. A low skill attacker can just steal the phone as most phones allow a user to answer a call without unlocking the device by default. A mid-tier attacker could social engineer a telco employee and SIM swap. A hypothetical state actor such as the Not-real Shueworld Adversary (NSA for short) may already have equipment in-path in collaboration with the service provider. Due to these factors and the lack of cryptography by default, this method is simply too insecure against a motivated, targeted adversary.

While the best defense is to prevent an attacker from getting on-path via BGP security, this cannot be done by a website and must be done by service providers. What websites could do is offer better authentication methods such as TOTP and FIDO2. And, critically, not allow telephony as a fallback if the user cannot authenticate by the more secure means. A chain is only as strong as its weakest link. 
