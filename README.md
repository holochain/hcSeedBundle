# hcSeedBundle

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Javascript SeedBundle parsing and generation library.

### Links

- [Git Repo - https://github.com/holochain/hcSeedBundle](https://github.com/holochain/hcSeedBundle)
- [API Documentation - https://holochain.github.io/hcSeedBundle/](https://holochain.github.io/hcSeedBundle/)

### Rationale

- Applications like Holochain have different requirements than classic blockchain system in terms of key management. Namely there is no need for read-only or hardened wallets (Holochain handles these concepts through capabilities and membranes).
- Applications like Holochain still have need of hierarchy and determinism in key (or in this case seed) derivation.
- Since we're using libsodium for hashing, signature, and encryption algorithms, let's use it for derivation as well.
- To be psychologically compatible with the [Bitcoin "HD Wallet" spec](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), we will do away with the "context" part of sodium KDF by always setting it to `b"SeedBndl"` and focusing on the `subkey_id` and can declare a chain of subsequent derivations of a 32 byte seed in the form `m/68/1/65/8` where we apply `subkey_id`s 68, 1, 65, then 8 in turn.

### Derivation Usage

```javascript
import { seedBundleReady, UnlockedSeedBundle } from 'hcSeedBundle'

// await library functions ready to call
await seedBundleReady

// generate a new pure entropy master seed
const master = UnlockedSeedBundle.newRandom({
  bundleType: 'master'
})

// derive a device root seed from the master
const deviceRoot = master.derive(68, {
  bundleType: 'deviceRoot'
})

// clear our secrets
master.zero()
deviceRoot.zero()
```

### Locking (encrypting) a SeedBundle

```javascript
import {
  seedBundleReady,
  parseSecret,
  UnlockedSeedBundle,
  SeedCipherPwHash
} from 'hcSeedBundle'

// await library functions ready to call
await seedBundleReady

// generate a new pure entropy master seed
const master = UnlockedSeedBundle.newRandom({
  bundleType: 'master'
})

// we need the passphrase as a Uint8Array
const pw = (new TextEncoder()).encode('test-passphrase')
const encodedBytes = master.lock([
  new SeedCipherPwHash(parseSecret(pw))
])

// clear our secrets
master.zero()
```

### Unlocking (decrypting) a SeedBundle

```javascript
import {
  seedBundleReady,
  parseSecret,
  UnlockedSeedBundle,
  LockedSeedCipherPwHash
} from 'hcSeedBundle'

// await library functions ready to call
await seedBundleReady

// decode the SeedCiphers that will let us unlock this bundle
const cipherList = UnlockedSeedBundle.fromLocked( /* encodedBytes here */ )

// we only support PwHash right now
if (!(cipherList[0] instanceof LockedSeedCipherPwHash)) {
  throw new Error('non-PwHash SeedCiphers not implemented')
}

// unlock with the passphrase
const pw = (new TextEncoder()).encode('test-passphrase')
const master = cipherList[0].unlock(parseSecret(pw))

// clear our secrets
master.zero()
```
