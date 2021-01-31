# Crypt Fetch for Spring Boot

This is a Spring Boot demo, how to use encrypted and signed communication for
Spring Boot applications.

# Theory Of Operation

This library uses X.509 client certificates, a well known and proven technology for
encryption and signing.

## How To Use

First, you have to implement interface PayloadIntf in your own class.
Second, you have to provide your new class at CryptFetchSpringApplication, method "message".

# Usecases

* Better protection for user credentials: Authentication is splitted from other functions and
user provided credentials are encrypted on a second stage on application layer. After first authentication
every request is authenticated by client certificates.
* No CSRF: Only users browser has access to its private key. Session hijacking becomes
nearly impossible as long browser is not infected by malware. 
* No insecure session handling: Every request is signed and encrypted on user side. Every response
is signed and encrypted on server side.

But: Every request needs to be authorized by application, otherwise you application has a security hole.

# File Structure

Where to find important files.

## Login

This package contains a Login class which must implement LoginIntf. It gets a CMS encrypted message
from client which contains a JSON object with following attributes:

* username
* password
* PKCS#10 certificate signing request

Login instance has to do following tasks:

* Decrypt CMS encrypted message by servers private key or using a HSM (hardware security module)
* Authenticate username/password: This may happen against a local solution, LDAP/Active Directory,
 a webservice, a SQL database or whatever you need.
* In case of successful authentication sign PKCS#10 request and reply with signed certificate.

This is the only critical path where a shared secret is used.

## resources

Beside application.properties and banner.txt there is one important file which needs to be
modified: **config.json**.

* "authURL": "http://127.0.0.1:8080/login",
* "messageURL": "http://127.0.0.1:8080/message",
* "renewURL": "http://127.0.0.1:8080/renew"

must be set to your server.

# How Deploy
 
    cd target/
    cp ../src/main/resources/config.json .
    gradle build
    java -jar crypt-fetch-spring-0.0.2-SNAPSHOT.jar 
 
# Security Considerations

This PoC makes web security infrastructure mostly useless due to encryption of payload
on application layer. A web application firewall is no longer able to check requests for malicious content.
WAF may still check a long (pem encoded) string in request, but it cannot decode payload.

On the other hand it is a great foundation for a powerful zero trust infrastructure on the
authentication layer. Due to the signature of every request, it can be considered as
authenticated. For a production deployment you should consider using a central PKI for
throwaway certificates.

Please be aware of that authorization of request is not in scope of this PoC.

# Status

Pre Alpha, mostly incomplete. Do not use in production environments.

# Associated Projects

* https://github.com/ip6li/crypt-fetch is a JavaScript based client implementation

# Credits

https://magnus-k-karlsson.blogspot.com/

