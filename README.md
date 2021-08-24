# hcSeedBundle

Javascript Holochain SeedBundle parsing and generation library.

### Documentation

[See our JSDoc Generated Documentation](https://holochain.github.io/keybundle-poc/)

### Derivation Usage

```javascript
import { seedBundleReady, UnlockedSeedBundle } from 'hcSeedBundle'

// await library functions ready to call
await seedBundleReady

// generate a new pure entropy master seed
const master = UnlockedSeedBundle.newRandom({
  bundleType: 'master'
})

// derive a device root seed from the baster
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
