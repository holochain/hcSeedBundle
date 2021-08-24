import assert from 'assert'
import {
  seedBundleReady,
  parseSecret,
  UnlockedSeedBundle,
  SeedCipherPwHash
} from '../index.js'

describe('SeedBundle Test Suite', () => {
  it('subseed key !== parent', async () => {
    await seedBundleReady

    const master = UnlockedSeedBundle.newRandom({
      bundleType: 'master'
    })

    const deviceRoot = master.derive(68, {
      bundleType: 'deviceRoot'
    })

    assert.notEqual(master.signPubKey, deviceRoot.signPubKey)

    master.zero()
    deviceRoot.zero()
  })

  it('lock/unlock key equality', async () => {
    await seedBundleReady

    const master = UnlockedSeedBundle.newRandom({
      bundleType: 'master'
    })

    const pw1 = (new TextEncoder()).encode('test-passphrase')
    const masterEncoded = master.lock([
      new SeedCipherPwHash(parseSecret(pw1), 'interactive')
    ])

    master.zero()

    const unlockCipherList = UnlockedSeedBundle.fromLocked(masterEncoded)

    const pw2 = (new TextEncoder()).encode('test-passphrase')
    const master2 = unlockCipherList[0].unlock(parseSecret(pw2), 'interactive')

    assert.equal(master.signPubKey, master2.signPubKey)

    master2.zero()
  })
})
