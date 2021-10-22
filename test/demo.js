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
        hcSeedBundle.parseSecret(pw), 'minimum')
    ])

    // -- if you want to regenerate for (decrypting) below:
    // console.log(encodedBytes.toString('base64'))

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
      'minimum'
    )])

    // clear our secrets
    master.zero()
  })

  it('Unlocking (decrypting) a SeedBundle', async () => {
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
  })
})
