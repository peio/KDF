KDF -  ISO 18033 Key derivation functions 
-----------------------------------------

Key derivation functions (KDF1,KDF2,KDF3,KDF4) as defined in section 6.2 of ISO 18033

A key derivation function is a function KDF (x, l) that takes as input an octet string x and
an integer l >= 0, and outputs an octet string of length l. The string x is of arbitrary length,
although an implementation may define a (very large) maximum length for x and maximum size
for l, and fail if these bounds are exceeded.


Read more on Victor Shoup's ISO Page: http://www.shoup.net/iso/