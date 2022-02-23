# EncryptedNet

Authenticated encryption of Roblox networking with ECDH key exchanges and ChaCha20 ciphering.

## Usage

This library returns a function that wraps your remotes, like so.

```Lua
-- Server
local AttemptLogin = EncryptedNet(Remotes.Server:Create("AttemptLogin"))

AttemptLogin:SetCallback(function(Player, password) -- Use normally
    -- ...
end)

--Client
local AttemptLogin = EncryptedNet(Remotes.Client:Get("AttemptLogin"))

AttemptLogin:CallServerAsync(password):andThen(function(response) -- Use normally
    -- ...
end)
```

While there's no difference to how you write your networking, this `EncryptedNet(remote)` wrapper is actually encrypting and signing all the traffic that flows through those remotes!

![demo](https://cdn.discordapp.com/attachments/711758878995513364/945726611641233469/unknown.png)

## How EncryptedNet works

When you `require()` EncryptedNet from the server, it sets up a RemoteFunction for a handshake. When you `require()` EncryptedNet from the client, it calls that handshake remote. The server and client each generate public & private keys, then send their public keys to each other. Using these keys, they perform an [Elliptic-curve Diffie–Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) key exchange to arrive at a shared secret that is later used to encrypt all traffic.

When the server calls `:SetCallback()` on a remote, the callback is actually set to a function that receives encrypted data and a signature. This function decrypts the data with the shared secret using the [ChaCha20 cipher](https://en.wikipedia.org/wiki/Salsa20#ChaCha20_adoption) (since ChaCha20 is efficient for non-hardware applications like ours), then verifies the decrypted data using the elliptic curve signature. Once it has done that, it passes the decrypted data to your specified callback function and your code runs none the wiser.

When a client calls `:CallServerAsync()` on a remote, it first takes your arguments and encrypts them with ChaCha20 and the shared secret, then creates a signature using your private key, and then sends those along.

This process is similarly done around `:Connect()`, `:SendToPlayer()`, etc. All of the RbxNet API is wrapped to properly handle authenticated encryption on all of your traffic on that remote.

## Credits

Absolutely *massive* shoutout to [PG23186706924](http://www.computercraft.info/forums2/index.php?/user/68959-pg23186706924/) for their [pure Lua implementation](http://www.computercraft.info/forums2/index.php?/topic/29803-elliptic-curve-cryptography/) of the elliptic curve cryptography tech that powers this library. I have ported it to Roblox and optimized it for Luau and it is wonderful.
