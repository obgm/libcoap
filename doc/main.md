libcoap                         {#mainpage}
=======

A C implementation of the Constrained Application Protocol (RFC 7252)
=====================================================================

Copyright (C) 2010--2024 by Olaf Bergmann <bergmann@tzi.org> and others

About libcoap
=============

libcoap is a C implementation of a lightweight application-protocol
for devices that are constrained their resources such as computing
power, RF range, memory, bandwidth, or network packet sizes. This
protocol, CoAP, is standardized by the IETF as RFC 7252. For further
information related to CoAP, see <https://coap.space> or
[CoAP Wiki](https://en.wikipedia.org/wiki/Constrained_Application_Protocol).

You might want to check out
[libcoap-minimal](https://github.com/obgm/libcoap-minimal) for usage
examples.

The following RFCs are supported

* [RFC7252: The Constrained Application Protocol (CoAP)](https://rfc-editor.org/rfc/rfc7252)

* [RFC7390: Group Communication for the Constrained Application Protocol (CoAP)](https://rfc-editor.org/rfc/rfc7390)

* [RFC7641: Observing Resources in the Constrained Application Protocol (CoAP)](https://rfc-editor.org/rfc/rfc7641)

* [RFC7959: Block-Wise Transfers in the Constrained Application Protocol (CoAP)](https://rfc-editor.org/rfc/rfc7959)

* [RFC7967: Constrained Application Protocol (CoAP) Option for No Server Response](https://rfc-editor.org/rfc/rfc7967)

* [RFC8132: PATCH and FETCH Methods for the Constrained Application Protocol (CoAP)](https://rfc-editor.org/rfc/rfc8132)

* [RFC8323: CoAP (Constrained Application Protocol) over TCP, TLS, and WebSockets](https://rfc-editor.org/rfc/rfc8323)

* [RFC8516: "Too Many Requests" Response Code for the Constrained Application Protocol](https://rfc-editor.org/rfc/rfc8516)

* [RFC8613: Object Security for Constrained RESTful Environments (OSCORE)](https://rfc-editor.org/rfc/rfc8613)

* [RFC8768: Constrained Application Protocol (CoAP) Hop-Limit Option](https://rfc-editor.org/rfc/rfc8768)

* [RFC8974: Extended Tokens and Stateless Clients in the Constrained Application Protocol (CoAP)](https://rfc-editor.org/rfc/rfc8974)

* [RFC9175: CoAP: Echo, Request-Tag, and Token Processing](https://rfc-editor.org/rfc/rfc9175)

* [RFC9177: Constrained Application Protocol (CoAP) Block-Wise Transfer Options Supporting Robust Transmission](https://rfc-editor.org/rfc/rfc9177)

There is (D)TLS support for the following libraries

* [OpenSSL](https://www.openssl.org) (Minimum version 1.1.0) [PKI, PSK and PKCS11]

* [GnuTLS](https://www.gnutls.org) (Minimum version 3.3.0) [PKI, PSK, RPK(3.6.6+) and PKCS11]

* [Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/) (Minimum version 2.7.10) [PKI and PSK]

* [TinyDTLS](https://github.com/eclipse/tinydtls) [PSK and RPK] [DTLS Only]

Documentation
=============

This set of pages contains the current set of documention for the libcoap APIs.

License Information
===================

This library is published as open-source software without any warranty
of any kind. Use is permitted under the terms of the simplified BSD
license. It includes public domain software. libcoap binaries may also
include open-source software with their respective licensing terms.
Please refer to
[LICENSE](https://raw.githubusercontent.com/obgm/libcoap/develop/LICENSE)
for further details in the source.
