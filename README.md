# ssrust

shadowsocks of rust impletation

## Supoorted features:
- [x] TCP
- [ ] UDP

## Supported ciphers:
- [x] aes_128_gcm
- [x] aes_256_gcm
- [x] chacha20_poly1305

Build
-----

    $ cargo build --release
    
Usage
-----    

    $ cd target/release/

    $ ./server --port <PORT> --password <PASSWORD> --method <METHOD>

    $ ./client --server <SERVER> --server-port <SERVER_PORT> --local-port <LOCAL_PORT> --password <PASSWORD> --method <METHOD>

--help for more detail

Example
-------

    $ ./server --port 8388 --password "barfoo!" --method chacha20-poly1305

    $ ./client --server 127.0.0.1 --server-port 8388  --local-port 1080 --password "barfoo!" --method chacha20-poly1305




