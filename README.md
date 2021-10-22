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
    // await library functions ready to call
    await hcSeedBundle.seedBundleReady

    // generate a new pure entropy master seed
    const master = hcSeedBundle.UnlockedSeedBundle.newRandom({
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
    // await library functions ready to call
    await hcSeedBundle.seedBundleReady

    // generate a new pure entropy master seed
    const master = hcSeedBundle.UnlockedSeedBundle.newRandom({
      bundleType: 'master'
    })

    // we need the passphrase as a Uint8Array
    const pw = (new TextEncoder()).encode('test-passphrase')
    const encodedBytes = master.lock([
      new hcSeedBundle.SeedCipherPwHash(
        hcSeedBundle.parseSecret(pw), 'minimum')
    ])

    // -- if you want to regenerate for (decrypting) below:
    // console.log(encodedBytes.toString('base64'))

    // clear our secrets
    master.zero()
```

### Locking (encrypting) a SeedBundle with Security Questions

```javascript
    // await library functions ready to call
    await hcSeedBundle.seedBundleReady

    // generate a new pure entropy master seed
    const master = hcSeedBundle.UnlockedSeedBundle.newRandom({
      bundleType: 'master'
    })

    // we need the answers as a Uint8Arrays
    const pw = pw => hcSeedBundle.parseSecret(
      (new TextEncoder()).encode(pw)
    )

    const encodedBytes = master.lock([
      new hcSeedBundle.SeedCipherSecurityQuestions([
        'Favorite Color?',
        'Favorite Hair?',
        'Favorite Food?'
      ], [
        pw('blue'),
        pw('big'),
        pw('begal')
      ],
      'minimum'
    )])

    // clear our secrets
    master.zero()
```

### Unlocking (decrypting) a SeedBundle

```javascript
    // await library functions ready to call
    await hcSeedBundle.seedBundleReady

    const encodedBytes = Buffer.from('k6VoY3NiMJGWonB32BIdrYjnnyFmjnPliWy14tDZzSAAAccYErS20d5w0QPg9NgApbNniDBToDq8Gn1Mm8cxEntSAEiSvIhJGV9Z/jsmJKVWxI1Endpj1QsIHKciZ46oyOWLrCRHTQjkX8FeZ86xBfvEE4GqYnVuZGxlVHlwZaZtYXN0ZXI=', 'base64')

    // decode the SeedCiphers that will let us unlock this bundle
    const cipherList = hcSeedBundle.UnlockedSeedBundle.fromLocked(encodedBytes)

    // the demo is encrypted with PwHash
    if (!(cipherList[0] instanceof hcSeedBundle.LockedSeedCipherPwHash)) {
      throw new Error('Expecting PwHash')
    }

    // unlock with the passphrase
    const pw = (new TextEncoder()).encode('test-passphrase')
    const master = cipherList[0].unlock(hcSeedBundle.parseSecret(pw))

    // clear our secrets
    master.zero()
```
