# Kraken: PlaidCTF 2023 Problem

![](https://img.shields.io/badge/Category-rev%2Fweb-brightgreen)
![](https://img.shields.io/badge/Author-luke-blue)
![](https://img.shields.io/badge/Testers-ricky%2C%20bluepichu-blueviolet)
![](https://img.shields.io/badge/🐙%20Flag-250%20points%2C%207%20solves-orange)

## Flavor Text

_Set sail for the most exclusive stolen NFTs in the digital seas with Kraken! Enjoy one rare collection per week valued at millions of doubloons, all for free!_

Website: `http://kraken.chal.pwni.ng`  
Flag Name: `🐙`  
Flag Description: _Hint: The server uses the same libraries as the client_

## Host

Players only need the link and the Flavor Text: http://kraken/chal.pwni.ng

Be sure to remove auth by commenting out `auth_basic` lines in `nginx/default.conf` before release.

Port **80/tcp** needs to be publicly accessible.

```
docker compose up --build
```

Confirm server and solution are working by running `go run .` in `cmd/solution/`

## About (spoilers)

Images are grabbed using a weird WireGuard+gvisor+wasm+websocket networking setup. WireGuard and Google's userspace TCP/IP stack are compiled to webassembly and communicate with the server using a websocket wrapper. Every image grab is effectively setting up a point-to-point VPN with ephemeral client keys and addresses.

The trick is that the server is protecting files with an IP whitelist. If you control your source address and are one hop away from the server, you can manipulate your source address without pesky intermediate routers getting in the way. This means you can throw weird packets with a source IP of `127.0.0.1` or `::1` at the server to see how it handles it. The server drops these "normal" localhost packets, but accepts ipv4-mapped localhost `::ffff::127.0.0.1` as `127.0.0.1`!

See https://github.com/google/gvisor/blob/e69c018749edd7c42098008ffd14a351060a3150/pkg/tcpip/network/ipv6/ipv6.go#L1095 for why this happens. The packet is sent through the IPv6 path, so is only checked against `::1`. Once it makes it through all of the packet checks, applications parse the address as `127.0.0.1`. Very similar to https://blog.cloudflare.com/cloudflare-handling-bug-interpreting-ipv4-mapped-ipv6-addresses/

Update: I filed a bug report that was addressed shortly after the CTF ended: https://github.com/google/gvisor/commit/ff4f0b9fc52b34f35ee17325572e585ad82e0c79

## Solution

Query file with address set to IPv4-mapped IPv6 address `::ffff:127.0.0.1`

Players are not expected to reimplement the client (although that's a valid solution). The hope is that players will dig into the WASM and patch memory or the function call that generates the address: `main.generateAddr`. The .wasm file is not stripped to make this easier.

One way to find the memory address that the IP address is written to is to use a tool like [Cetus](https://github.com/Qwokka/Cetus) to search for the address in memory _after_ the websocket request has been made. The problem is that thousands of locations have the IP address, presumably because the address ends up in memory when sending/receiving packets. If you click to load the flag instead of the working images, fewer packets are sent so only tens of addresses have the address. The first one that Cetus finds is the first to be generated (because of how Go's WASM stacks work), so that's the one that needs to be modified/patched. To confirm this, use Cetus' `freeze` feature to not allow that location to be written. The query parameter of the next websocket request will reflect whichever value you place in that address.

Unfortunately, Cetus does not allow you to write and freeze multiple values at once or modify values while at a breakpoint, so you need to modify memory manually. Chrome easily allows modification of memory though so it's trivial to set a breakpoint after the address is written and then modify to your heart's content:

```javascript
let b = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];
let view = new DataView($mem.buffer);
let start = 0x81e790;
for (let i = 0; i < b.length; i++) {
  view.setUint8(start + i, b[i]);
}
```

Resuming execution will fetch the flag with a local address and return the flag image containing the flag string.
