# Overview

This project builds the saltunnel-client and saltunnel-server programs, whic are used in conjunction to establish a cryptographically secure, difficult-to-censor, TCP tunnel using symmetric key cryptography.  This allows one to augment a normally-insecure TCP session with state-of-the-art security, with minimal hassle and minimal impact on performance.

# Installation

As a prerequisite, you must first have `libsodium` installed.  

To compile and install `saltunnel` from source:

```
git clone https://github.com/notfed/saltunnel.git
cd saltunnel.git
sh autogen.sh
./configure
make
sudo make install
```

# Documentation

See `saltunnel(1)` for complete documentation.
