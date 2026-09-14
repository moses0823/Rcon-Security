# RconSecurity

RconSecurity 是 Paper/Folia 26.2 的額外 Secure RCON Authentication Gateway。它**不修改、取代或攔截 Minecraft 原生 RCON authentication**；原生 RCON 仍由 Minecraft 使用 `rcon.port` 與 `rcon.password` 正常提供。

## 架構

建議將 Minecraft 原生 RCON 綁定在 localhost，只讓本機上的 Gateway 存取：

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

Gateway 預設監聽 `0.0.0.0:25576`，原生 RCON 預設連線 `127.0.0.1:25575`。Gateway 只有在認證成功後，才會建立到原生 RCON 的連線並轉送 command。

此協議提供 authentication、replay protection、rate limiting 與封包驗證，但目前不加密 command traffic。若 Gateway 暴露在不可信網路，請搭配 VPN、私有網路或其他傳輸層加密方案。

## 需求

- Java 25
- Paper 或 Folia 26.2
- Gradle Wrapper（專案已包含）

## 使用前提

請將本專案建置出的 `RconSecurity` JAR 安裝到 Minecraft server 的
`plugins` 目錄並啟用插件。外部 Secure RCON 連線必須使用相容的
[moses0823/Rcon-tui](https://github.com/moses0823/Rcon-tui) 用戶端；一般 Minecraft RCON client 無法使用本插件的
challenge-response 協議。

## 建置

Windows：

```text
gradlew.bat build
```

Linux/macOS：

```text
./gradlew build
```

輸出位於 `build/libs/RconSecurity-1.0.0.jar`。

## 安裝與設定

1. 將 JAR 放入伺服器的 `plugins` 目錄。
2. 啟動一次伺服器，讓插件產生設定與 Client Secret。
3. 在 `plugins/RconSecurity/config.yml` 設定各 Client。
4. 將 `native-rcon.password` 設為 Minecraft 原生 RCON 密碼。這是 Proxy 到原生 RCON 使用的內部密碼，絕不會傳給 Secure RCON Client。
5. 確認 `server.properties` 的原生 RCON 只綁定 localhost，並以防火牆限制 Gateway port。

`CHANGE-ME` 的 Client Secret 會在首次啟動時以 `SecureRandom` 產生 256-bit Base64 Secret。請保護 `config.yml`，不要將產生後的設定檔提交到公開版本庫，也不要把 Secret 放入 log。

## Secure Protocol

每個封包都是 big-endian length-prefixed frame：

```text
MAGIC (4 bytes) | VERSION (2 bytes) | MESSAGE_TYPE (1 byte) | PAYLOAD_LENGTH (4 bytes) | PAYLOAD
```

目前版本為 `1`，Magic 為 ASCII `RSEC`，最大封包大小預設為 4096 bytes。流程如下：

1. Client 傳送 `HELLO`，payload 是 `uint16 length + UTF-8 Client ID`。
2. Server 傳送 32-byte random Nonce、Server Unix time 與 Time Counter。
3. Client 傳送 Nonce 與 32-byte HMAC-SHA256 response。
4. HMAC message 為 `ClientId UTF-8 bytes + TimeCounter big-endian int64 + Nonce bytes`。
5. Server 驗證 Client 是否啟用、time window、Nonce 一次性使用狀態與 constant-time HMAC 相等性。
6. 認證成功後，Client 傳送 UTF-8 command，Gateway 透過原生 RCON 執行並回傳結果。

Time step 預設為 30 秒，允許目前、前一個與下一個 time window。每個 Nonce 至少 256 bit 且具備過期時間，只能成功消耗一次。

## 管理指令

權限：`rconsecurity.admin`

- `/rconsecurity reload`
- `/rconsecurity status`
- `/rconsecurity clients`
- `/rconsecurity block <ip>`
- `/rconsecurity unblock <ip>`

所有網路 I/O 都在插件自己的 executor 執行；插件不使用 Bukkit global scheduler，也不在網路執行緒直接操作 Bukkit/Folia API，因此可在 Paper 與 Folia 上運作。
