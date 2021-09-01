import assert from 'assert'
import * as hcSeedBundle from '../index.js'
import fixtures from './seed_bundle_test_fixtures.js'

import _sodium from 'libsodium-wrappers'

describe('Demo Tests Copied to README.md', () => {
  it('Derivation Usage', async () => {
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
  })

  it('Locking (encrypting) a SeedBundle', async () => {
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
        hcSeedBundle.parseSecret(pw), 'interactive')
    ])

    // clear our secrets
    master.zero()
  })

  it('Locking (encrypting) a SeedBundle with Security Questions', async () => {
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
      'interactive'
    )])

    // clear our secrets
    master.zero()
  })

  it('Unlocking (decrypting) a SeedBundle', async () => {
    // await library functions ready to call
    await hcSeedBundle.seedBundleReady

    const encodedHex = '93a568637362309196a27077d812482bfe23f93b21311bf50e96ece34dedce0400000002c718122a108ef8fd0568658b0af82ec194f70ae147aecf89a9845dc73112f6a92e61911d9211ee8152d2de8a8630c1a32b96167e0a9e22eb2516b33d51b5e8745367ee8140cd010aa01e749b41154ec41381aa62756e646c6554797065a66d6173746572'

    const encodedBytes = new Uint8Array(
      encodedHex.match(/.{1,2}/g).map(b => parseInt(b, 16)))

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
  })
})
