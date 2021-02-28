# JSON Formats

This file describes JSON schemas used in this project.

# Login

Credentials are encryped on client side with server certificate provided by /config URL.

```
{
  "credentials": {
    "password": "myPassword",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICWDCCAUACAQAwEzERMA8GA1UEAxMIQ049Y2VydDEwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQCfST14JctSmvejHkmFZcHq8S5DVbw/LmWEDq90wQCG\nkzsXA8b8K+qIu/dhCf1blQx9J8XekH2f7rEWQobcdrIZqJsVmk13kmwkRJbqiug9\n/Pm/FyAgnSQ6vkDLPMXi3ut1oG9xm17cJ/pWezueBZZpGf6gZ8mt6mVw+DMPjoq2\nHv179qs/vTkSeQfU0FsvI7+NFzbGoGsWuu2qZ0naCjly9b4yoWwV15TRogcVN0ht\n9S1UQdVfIuJLwU9ea3hAxxVoEKC6cEpL7hTepVBsV6FBWZboR4XOPjakNh6TJqxI\nHaR6sjvDcV9EsJYUgzN4CmWfO1r4L4hUqjpzAa1A5Dn3AgMBAAGgADANBgkqhkiG\n9w0BAQsFAAOCAQEAdxb7xFwQk2wn0iqLJ8l9W6ot344P1nAvE87Cvrjc8Y7uuTUP\nntsk6w98UGB0plrya6m+pZJ8hUFFFMhfUVg6FIHsA/VG2Xb1cCk/jRngJB0oJ+d8\n3ACvVd6jzDIKvw1JpDZFKxw/flPd5lQjADge+dmj0cQlEWDAUfTboKyzXJZKJ+/N\nE0H+kxz1/NjiY/irLP/iBkiz/oIBzhV2wCK4F+yR8lBs7LQeQriRMBi4u4dbQ1IB\n99RDNU7BjFzL5n6uCppis6AQHthgQ0L51KaV3TWuLGeufbV8a3JQR6mNtJsQIAiv\nDM9flwMnxq1od8mxhPOAmgpkCoIWpB8uciATJA==\n-----END CERTIFICATE REQUEST-----",
    "username": "myUserName"
  }
}
```

If login ist successful reply is a client certificate created from clients public key and signed by a CA.
