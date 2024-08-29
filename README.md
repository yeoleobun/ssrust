# ssrust

shadowsocks of rust impletation

## Supoorted features:
- [x] TCP
- [ ] UDP

## Supported ciphers:
- [x] aes-128-gcm
- [x] aes-256-gcm
- [x] chacha20-poly1305

Build
-----

    $ cargo build --release

Usage
-----

    $ cd target/release/

    $ ./server --address <ADDRESS> --password <PASSWORD> --method <METHOD>

    $ ./client --remote-addr <REMOTE_ADDR> --local-addr <LOCAL_ADDR> --password <PASSWORD> --method <METHOD>

--help for more detail

Example
-------

    $ ./server --address 0.0.0.0:8388 --password barfoo! --method chacha20-poly1305

    $ ./client --remote-addr localhost:8388 --local-addr localhost:1080 --password barfoo! --method chacha20-poly1305
