# ws28
C++14 WebSocket server library

## Do you use this in production?

Yes.

## Should I use this in production?

Maybe.

## Is it spec compliant?

Mostly. It doesn't do the closing handshake properly (it simply kills the connection). Everything else should be spec compliant.

## How do I use this?

1. Copy the source files into your project, I don't like making libraries.

2. Create a server:

    ws28::Server server{uv_default_loop(), SSL_CTX* or NULL};

Note: if you have a secure server, it'll actually listen for both secure and insecure connections on that same port
by sniffing the first byte. This allows you to run insecure websocket servers on port 443 and not deal with the swarm
of broken proxies out there.

3. Set up some callbacks

    See `src/Server.h`.

4. Listen

    server.Listen(port);

## What's the license?

Most files are MIT. The base64 and sha1 code are BSD, feel free to pull request some MIT licensed code to replace those.
