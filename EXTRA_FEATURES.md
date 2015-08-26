## EXTRA_FEATURES

MarshalDER
uses
http://linux.die.net/man/3/i2d_x509_bio

LoadCertificateFromDER
uses the bio with
https://www.openssl.org/docs/manmaster/crypto/d2i_X509.html


you also have the functions
 X509 *d2i_X509(X509 **px, const unsigned char **in, int len);
 int i2d_X509(X509 *x, unsigned char **out);

as described here https://www.openssl.org/docs/manmaster/crypto/d2i_X509.html

MarshalPKCS1PublicKeyDER