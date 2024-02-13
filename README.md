# Chacha20

initial implementation of chacha20 up until section 2.4

tests have been passed for sections 2.1, 2.2 and 2.3 and 2.4



I had some issues related to reading binary data. After lots of non trivial investigation, I realized it's related to how C handles signed vs unsigned chars. So even if the pipeline worked without hiccups with clear plain text, it was a mess with ciphertext.bin

This issue is now fixed


