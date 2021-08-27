import assert from 'assert'
import {
  seedBundleReady,
  parseSecret,
  UnlockedSeedBundle,
  SeedCipherPwHash,
  SeedCipherSecurityQuestions,
} from '../index.js'
import fixtures from './seed_bundle_test_fixtures.js'

import _sodium from 'libsodium-wrappers'

async function generate (s) {
  const master = UnlockedSeedBundle.newRandom({})

  const cList = []
  for (const u of s.unlock) {
    if (u.type === 'pwHash') {
      const pw = (new TextEncoder()).encode(u.passphrase)
      cList.push(new SeedCipherPwHash(parseSecret(pw), 'interactive'))
    } else {
      throw new Error('invalid SeedCipher: ' + JSON.stringify(u))
    }
  }

  const masterEncoded = master.lock(cList)

  return _sodium.to_base64(masterEncoded, _sodium.base64_variants.URLSAFE_NO_PADDING)
}

describe('SeedBundle Test Suite', () => {
  before(async () => {
    await _sodium.ready

    for (let fi = 0; fi < fixtures.success.length; ++fi) {
      const fixt = fixtures.success[fi]

      if (!fixt.cipher) {
        throw new Error('required cipher, like: ' + await generate(fixt))
      }

      fixt.cipher = _sodium.from_base64(fixt.cipher, _sodium.base64_variants.URLSAFE_NO_PADDING)
    }
  })

  for (let fi = 0; fi < fixtures.success.length; ++fi) {
    const fixt = fixtures.success[fi]
    describe('fixture-success-test-' + fi, () => {
      it('unlock and derive', async () => {
        const cList = UnlockedSeedBundle.fromLocked(fixt.cipher)
        assert.equal(cList.length, fixt.unlock.length)

        const sList = []
        for (let ui = 0; ui < fixt.unlock.length; ++ui) {
          const unlock = fixt.unlock[ui]
          const seedCipher = cList[ui]
          if (unlock.type === 'pwHash') {
            const pw = (new TextEncoder()).encode(unlock.passphrase)
            sList.push(seedCipher.unlock(parseSecret(pw), 'interactive'))
          } else {
            throw new Error('invalid SeedCipher: ' + seedCipher)
          }
        }

        for (const cmp of sList) {
          assert.equal(fixt.signPubKey, cmp.signPubKey)
        }

        for (const path in fixt.derivations) {
          const signPubKey = fixt.derivations[path]
          let cur = sList[0]
          for (const id of path.split('/')) {
            if (id === 'm') {
              continue
            }
            cur = cur.derive(id|0)
          }
          assert.equal(signPubKey, cur.signPubKey)
        }
      })
    })
  }

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

  it('lock/unlock pwHash key equality', async () => {
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

  it('lock/unlock securityQuestion key equality', async () => {
    await seedBundleReady

    const master = UnlockedSeedBundle.newRandom({
      bundleType: 'master'
    })

    const q1 = 'What was the name of your first pet?'
    const q2 = 'What was the model of your first car?'
    const q3 = 'What are you most afraid of?'

    const a1 = (new TextEncoder()).encode('Fred  ')
    const a2 = (new TextEncoder()).encode(' PinTo')
    const a3 = (new TextEncoder()).encode('\tZoMbies')
    const masterEncoded = master.lock([
      new SeedCipherSecurityQuestions([
          q1,
          q2,
          q3
        ],
        [
          parseSecret(a1),
          parseSecret(a2),
          parseSecret(a3)
        ],
        'interactive'
      )
    ])

    master.zero()

    const unlockCipherList = UnlockedSeedBundle.fromLocked(masterEncoded)

    assert.deepEqual([q1, q2, q3], unlockCipherList[0].getQuestionList())

    const b1 = (new TextEncoder()).encode('FreD\n')
    const b2 = (new TextEncoder()).encode('PINTO')
    const b3 = (new TextEncoder()).encode('\t\tZombies')
    const master2 = unlockCipherList[0].unlock([
      parseSecret(b1),
      parseSecret(b2),
      parseSecret(b3)
    ], 'interactive')

    assert.equal(master.signPubKey, master2.signPubKey)

    master2.zero()
  })
})
