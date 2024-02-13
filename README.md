# Chacha20

## project presentation:

This is a C implementation of Chacha20 based on RFC-7539.
Chacha20 is a symmetric ecryption faster (faster than AES), usually used with Poly-1305 MAC.

## usage:
this is command line program taking 4 arguments:

    *the name of a file containing a 64-byte key (as binary data, not hex-encoded).
    *a 24-character hexadecimal string representing a 12-byte nonce
    *the name of the input file (binary data)
    *the name of the (new) output file (binary data)

## testing:
you can use the joint binary keyfile to this project, along with the screentext and the resulting cipher text.
encoding and decoding work similarly as tested with my_screen.txt and my_cipher.txt


