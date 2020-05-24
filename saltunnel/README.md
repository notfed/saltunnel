# saltunnel

## What is saltunnel?

`saltunnel` is a cryptographically secure, difficult-to-censor, TCP tunnel.  It allows one to augment a normally-insecure TCP session with state-of-the-art security, with minimal hassle and minimal impact on performance.

For more information, see https://identity.pub/saltunnel.

# How do I install it?

As a prerequisite, you must first have [libsodium](https://github.com/jedisct1/libsodium) installed.  

To compile and install `saltunnel` from source:

```
git clone https://github.com/notfed/saltunnel.git
cd saltunnel.git
sh autogen.sh
./configure
make
sudo make install
```

# How do I use it?

See or https://identity.pub/saltunnel or `saltunnel(1)` for complete documentation.
