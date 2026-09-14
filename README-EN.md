# RconSecurity

RconSecurity is an additional Secure RCON Authentication Gateway for Paper/Folia 26.2. It **does not modify, replace, or intercept Minecraft's native RCON authentication**. Native RCON continues to be provided normally by Minecraft using `rcon.port` and `rcon.password`.

## Architecture

It is recommended to bind Minecraft's native RCON to localhost and only allow the local Gateway to access it:

```text
Minecraft Native RCON
        |
        | bind to 127.0.0.1:25575
        v
Secure RCON Gateway (RconSecurity)
        |
        | Challenge-Response HMAC-SHA256
        v
Internet / Secure RCON Client
```

The Gateway listens on `0.0.0.0:25576` by default, while native RCON uses `127.0.0.1:25575` by default.

The Gateway only establishes a connection to native RCON and forwards commands after successful authentication.

The protocol provides authentication, replay protection, rate limiting, and packet validation. However, command traffic is **not encrypted**.

If the Gateway is exposed to an untrusted network, use a VPN, private network, or another transport-layer encryption solution.

## Requirements

* Java 25
* Paper or Folia 26.2
* Gradle Wrapper (included with the project)

## Prerequisites

Build this project and install the resulting `RconSecurity` JAR in the
Minecraft server's `plugins` directory, then enable the plugin. External
Secure RCON connections must use a compatible [moses0823/Rcon-cli](https://github.com/moses0823/Rcon-cli) client; ordinary
Minecraft RCON clients do not support this plugin's challenge-response
protocol.

## Building

### Windows

```text
gradlew.bat build
```

### Linux/macOS

```text
./gradlew build
```

The resulting JAR will be located at:

```text
build/libs/RconSecurity-1.0.0.jar
```

## Installation and Configuration

1. Place the JAR file into the server's `plugins` directory.
2. Start the server once to generate the configuration and Client Secret.
3. Configure individual clients in `plugins/RconSecurity/config.yml`.
4. Set `native-rcon.password` to the Minecraft native RCON password. This is the internal password used by the Gateway to connect to native RCON and is **never transmitted to the Secure RCON Client**.
5. Make sure the native RCON endpoint is restricted to localhost and use your firewall to restrict access to the Gateway port.

The `CHANGE-ME` Client Secret is automatically replaced on the first startup with a 256-bit Base64-encoded Secret generated using `SecureRandom`.

Protect `config.yml`. Do not commit the generated configuration file to a public repository, and never expose the Secret in logs.

## Secure Protocol

Each packet uses a big-endian length-prefixed frame:

```text
MAGIC (4 bytes) | VERSION (2 bytes) | MESSAGE_TYPE (1 byte) | PAYLOAD_LENGTH (4 bytes) | PAYLOAD
```

The current protocol version is `1`, and the Magic value is the ASCII string `RSEC`.

The maximum packet size is 4096 bytes by default.

The authentication process is:

1. The Client sends `HELLO`, with a payload containing `uint16 length + UTF-8 Client ID`.
2. The Server sends a 32-byte random Nonce, the Server Unix time, and the Time Counter.
3. The Client sends the Nonce and a 32-byte HMAC-SHA256 response.
4. The HMAC message is constructed from `ClientId UTF-8 bytes + TimeCounter big-endian int64 + Nonce bytes`.
5. The Server verifies that the Client is enabled, the time window is valid, the Nonce has not been used, and the HMAC matches using a constant-time comparison.
6. After successful authentication, the Client sends a UTF-8 command. The Gateway executes the command through native RCON and returns the result.

The default time step is 30 seconds, with the current, previous, and next time windows accepted.

Each Nonce is at least 256 bits, has an expiration time, and can only be successfully consumed once.

## Administrative Commands

Permission:

```text
rconsecurity.admin
```

Commands:

```text
/rconsecurity reload
/rconsecurity status
/rconsecurity clients
/rconsecurity block <ip>
/rconsecurity unblock <ip>
```

All network I/O is performed using the plugin's own executor.

The plugin does not use the Bukkit global scheduler and does not directly access the Bukkit/Folia API from network threads.

This allows RconSecurity to operate on both Paper and Folia.
