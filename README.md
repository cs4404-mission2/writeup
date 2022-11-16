# CS4404 Mission 2(FA)
Jake Ellington and Nate Sales

# Reconnaissance
## SMS

## FIDO
FIDO2 is an authentication mechanism that uses asymmetric key signing. When a FIDO2 device is added as an MFA method to a website, the website stores the device's public key. Subsequently when the user logs in, the website sends a challenge to the device, which signs the challenge with its private key and sends the signed message back to be verified with the public key. 

The security goal of this factor is authenticity. It proves that the person attempting to access the account has a FIDO2 device with a private key that corresponds to the public key that the server knows. This method assumes that the server generates unique challenges, that the FIDO2 key does not divulge its private key, and that the hardware token can be trusted.

### Failures
A notable failure of a FIDO2 device was the audit of the NirtoKey FIDO usb token including the disclosure of CVE-2020-12061 which scored 9.8. 


## Telephone

# Infrastructure
The infrastructure for this project consists of a web server, an automated VOIP system that dials users and promps for authentication, and corresponding VOIP infrastructure to allow the calls to be placed.

## Webserver
The webserver for this project is a modified version of the voting server from mission 1. It is a Rust binary built with the Rocket API with an sqlite database to keep track of user data and credentials. Asanonymity is not a security goal of this system, user authorization is verified with an encrypted cookie whose content is the user's username and a flag indicating wheather or not the user has authenticated via phone. This cannot be faked by the client as the cookie is signed and encrypted with a key known only to the server. 

When A user logs in to the webserver, it hashes their password with Argon2 and compares it with the user's record in the databse. If these match, the user is gnven the afforementioned cookie with the MFA flag set to zero. For example, the user `jmellington`'s cookie's decrypted value would be `jmellington0`. The client browser is then redirected to the content page that checks for the authorization cookie when the page is loaded. If the cookie is not present or invalid, the user gets sent back to the login page. If the cookie is present but the MFA flag is unset, the database is queried to see if the user did complete MFA since the last check and updates the flag accordingly. If the user has not, the webserver updates the database to request an MFA event for the user from the autodialer. If the user did complete MFA, the user's token is re-issued with the MFA flag set, and the homepage will display its content. 

## Autodialer

