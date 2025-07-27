# ws28
C++17 WebSocket server library

## Do you use this in production?

[Yes](https://diep.io/).

## Should I use this in production?

Maybe.

## Is it spec compliant?

Mostly. There's no UTF-8 validation. Everything else should be spec compliant.

## How do I use this?

1. Copy the source files into your project, I don't like making libraries.

2. Create a server:

```c++
ws28::Server server{uv_default_loop(), SSL_CTX* or nullptr};
```

Note: if you have a secure server, it'll actually listen for both secure and insecure connections on that same port
by sniffing the first byte. This allows you to run insecure websocket servers on port 443 and not deal with the swarm
of broken proxies out there.

3. Set up some callbacks

    See `src/Server.h`. But basically, you need some or all of these methods from `ws28::Server`: `SetClientConnectedCallback`, `SetClientDisconnectedCallback`, `SetClientDataCallback`, `SetCheckConnectionCallback` and `SetHTTPCallback`.

4. Listen

```c++
server.Listen(port);
```

You can also check `echo.cpp` for an echo server implementation.

## What's the license?

All files are under MIT license.

## More FAQ

### Can I store pointers to `ws28::Client`?

Only between ClientConnected and ClientDisconnected callbacks for each client. It is deleted immediately after ClientDisconnected.
