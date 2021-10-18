# eidc32proxy

This project includes library code and sample applications for interacting with
Stanley/3xLogic/Infinias eIDC32 door controller / badge reader devices and the
Intelli-M server which manages them.

The capabilities of this repository were [demonstrated at DEFCON 28](https://www.youtube.com/watch?v=ghiHXK4GEzE&t=5595s)
by friends [Babak Javadi](https://twitter.com/babakjavadi) and [Iceman](https://twitter.com/herrmann1001).

The library has three major components:

- An eIDC32 client emulator
- An Intelli-M server emulator
- A flexible proxy with a mangle feature (think: iptables jump-to-mangle-chain)
which supports insertion/suppresion/modification of upstream and downstream
messages. Using the proxy mangle capability, you can create log-free master
keys, suppress log events, change door schedules, etc...

There are a handful of sample applications in the `cmd/` directory.
`cloudkey_master_key` is the one demonstrated in the DEFCON presentation.
