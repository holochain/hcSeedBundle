import _sodium from 'libsodium-wrappers'
import msgpack from 'msgpack-lite'

const _sodiumCfg = {
  sodiumReady: false
}

/**
 * Await this promise once before calling functions in this library.
 */
export const seedBundleReady = _sodium.ready.then(() => {
  _sodiumCfg.sodiumReady = true
})

/**
 * Internal helper for ensuring the _sodium lib is ready
 *
 * @private
 */
function checkSodiumReady () {
  if (!_sodiumCfg.sodiumReady) {
    throw new Error('seedBundle library not ready. Await "seedBundleReady" first.')
  }
}

/**
 * Helper class that makes securing secrets easier by hiding them
 * in closures as additional protection against accidental exposure
 * via debugging, etc.
 * Note, when done with this secret, call `zero()` to clear the memory,
 * but be warned that this is javascript, and that is no guarantee
 * against exposure.
 *
 * @private
 */
class PrivSecretBuf {
  constructor (secret) {
    checkSodiumReady()

    if (!(secret instanceof Uint8Array)) {
      throw new Error('secret must be a Uint8Array')
    }

    if (_sodium.is_zero(secret)) {
      throw new Error('secret cannot be a zeroed Uint8Array')
    }

    // setup some config to track our zero status
    const cfg = {
      didZero: false
    }

    // closure to return secret if not zeroed
    const get = () => {
      if (cfg.didZero) {
        throw new Error('cannot access secret, already zeroed')
      }
      return secret
    }

    // closure to zero our secret
    const zero = () => {
      _sodium.memzero(secret)
      cfg.zero = true
    }

    // closure to derive an ed25519 signature pubkey from secret
    // if the secret is a passphrase, this will probably fail
    const deriveSignPubKey = () => {
      if (cfg.didZero) {
        throw new Error('cannot access secret, already zeroed')
      }
      if (secret.length !== 32) {
        throw new Error('can only derive secrets of length 32')
      }

      const { publicKey, privateKey } = _sodium.crypto_sign_seed_keypair(secret)
      _sodium.memzero(privateKey)
      return _sodium.to_base64(publicKey, _sodium.base64_variants.URLSAFE_NO_PADDING)
    }

    // closure to derive a sub-secret
    // if the secret is a passphrase, this will probably fail
    const derive = (subkeyId) => {
      if (cfg.didZero) {
        throw new Error('cannot access secret, already zeroed')
      }
      if (secret.length !== 32) {
        throw new Error('can only derive secrets of length 32')
      }
      const newSecret = _sodium.crypto_kdf_derive_from_key(32, subkeyId, 'HoloSeed', secret)
      return new PrivSecretBuf(newSecret)
    }

    Object.defineProperties(this, {
      get: { value: get },
      zero: { value: zero },
      deriveSignPubKey: { value: deriveSignPubKey },
      derive: { value: derive }
    })

    Object.freeze(this)
  }
}

/**
 * Injest a Uint8Array as an internal secret buffer.
 * Note, this buffer will be zeroed internally.
 *
 * @param {Uint8Array} secret the secret to injest.
 */
export function parseSecret (secret) {
  checkSodiumReady()
  return new PrivSecretBuf(secret)
}

/**
 * helper to translate limit names into values
 *
 * @private
 */
function privTxLimits (limitName) {
  let opsLimit = _sodium.crypto_pwhash_OPSLIMIT_MODERATE
  let memLimit = _sodium.crypto_pwhash_MEMLIMIT_MODERATE

  if (limitName === 'interactive') {
    opsLimit = _sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
    memLimit = _sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  } else if (limitName === 'sensitive') {
    opsLimit = _sodium.crypto_pwhash_OPSLIMIT_SENSITIVE
    memLimit = _sodium.crypto_pwhash_MEMLIMIT_SENSITIVE
  } else if (!limitName || limitName === 'moderate') {
    /* pass */
  } else {
    throw new Error('invalid limitName: ' + limitName)
  }

  return { opsLimit, memLimit }
}

/**
 * Base class for concrete SeedCiphers.
 */
export class SeedCipher {
  /**
   * Don't use this directly, use a sub-class.
   */
  constructor () {
    checkSodiumReady()
  }

  /**
   * Clear out any secret data maintained by this cipher
   */
  zero () {
    throw new Error('SeedCipher.zero is not callable on base class')
  }

  /**
   * Generate an encrypted seedCipher for given secretSeed
   *
   * @param {PrivSecretBuf} - parseSecret(Uint8Array)
   */
  encryptSeed (secretSeed) {
    throw new Error('SeedCipher.encryptSeed is not callable on base class')
  }
}

/**
 * Base class for unlocking an encrypted seedCipher.
 */
export class LockedSeedCipher {
  #finishUnlockCb

  /**
   * Don't use this directly, use a sub-class.
   */
  constructor (finishUnlockCb) {
    checkSodiumReady()

    this.#finishUnlockCb = finishUnlockCb
  }

  /**
   * Once the secretSeed is decrypted, subclass instances will call this
   * to generate the actualy UnlockedSeedBundle instance.
   */
  finishUnlock (secretSeed) {
    return this.#finishUnlockCb(secretSeed)
  }
}

/**
 * Straight up pwhashed passphrase type SeedCipher
 */
export class SeedCipherPwHash extends SeedCipher {
  #passphrase
  #limitName

  /**
   * Build this with
   *
   * @param {PrivSecretBuf} - parseSecret(Uint8Array)
   * @param {string} [limitName] - optional limitName (['interactive', 'moderate' *default*, 'sensitive'])
   */
  constructor (passphrase, limitName) {
    super()
    if (!(passphrase instanceof PrivSecretBuf)) {
      throw new Error('passphrase required, construct with parseSecret()')
    }
    this.#passphrase = passphrase
    this.#limitName = limitName
  }

  /**
   * Clear secret data
   */
  zero () {
    this.#passphrase.zero()
  }

  /**
   * Encrypte a secretSeed SeedCipher with this instance.
   * @param {PrivSecretBuf} - parseSecret(Uint8Array)
   */
  encryptSeed (secretSeed) {
    if (!(secretSeed instanceof PrivSecretBuf)) {
      throw new Error('secretSeed must be an internal secret buffer')
    }

    const salt = _sodium.randombytes_buf(16)

    const { opsLimit, memLimit } = privTxLimits(this.#limitName)

    // generate secret from pwhash
    const secret = _sodium.crypto_pwhash(
      32,
      this.#passphrase.get(),
      salt,
      opsLimit,
      memLimit,
      _sodium.crypto_pwhash_ALG_ARGON2ID13
    )

    // initialize encryption
    const { state, header } = _sodium
      .crypto_secretstream_xchacha20poly1305_init_push(secret)

    _sodium.memzero(secret)

    // encrypt our inner secret data
    const cipher = _sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      secretSeed.get(),
      null,
      _sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    )

    return {
      type: 'pwHash',
      salt,
      seedCipherHeader: header,
      seedCipher: cipher
    }
  }
}

/**
 * Unlock a SeedCipher with a straight forward pwhashed passphrase.
 */
export class LockedSeedCipherPwHash extends LockedSeedCipher {
  #salt
  #header
  #cipher

  /**
   * You won't use this directly, call UnlockedSeedBundle.fromLocked()
   *
   * @param {function} - the finishUnlock callback function
   * @param {Uint8Array} - argon salt
   * @param {Uint8Array} - secretstream header
   * @param {Uint8Array} - secretstream cipher
   */
  constructor (finishUnlockCb, salt, header, cipher) {
    super(finishUnlockCb)
    this.#salt = salt
    this.#header = header
    this.#cipher = cipher
  }

  /**
   * Unlock to an UnlockedSeedBundle
   *
   * @param {PrivSecretBuf} - parseSecret(Uint8Array)
   * @param {string} [limitName] - optional limitName (['interactive', 'moderate' *default*, 'sensitive'])
   */
  unlock (passphrase, limitName) {
    if (!(passphrase instanceof PrivSecretBuf)) {
      throw new Error('passphrase required, construct with parseSecret()')
    }

    const { opsLimit, memLimit } = privTxLimits(limitName)

    // generate secret from pwhash
    const secret = _sodium.crypto_pwhash(
      32,
      passphrase.get(),
      this.#salt,
      opsLimit,
      memLimit,
      _sodium.crypto_pwhash_ALG_ARGON2ID13
    )

    passphrase.zero()

    // initialize decryption
    const state = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(
      this.#header,
      secret
    )

    _sodium.memzero(secret)

    // finalize decryption
    const res = _sodium.crypto_secretstream_xchacha20poly1305_pull(state, this.#cipher)
    if (!res) {
      throw new Error('failed to decrypt bundle')
    }
    const { message } = res

    return this.finishUnlock(parseSecret(message))
  }
}

/**
 * Represents a seed bundle with access to secret seeds for derivation.
 *
 * WARNING: Before forgetting about an UnlockedKeyBundle instance, you
 * should probably call the `zero` function to clear the internal secret data.
 * HOWEVER, being javascript, there is no guarantee we haven't leaked
 * secret data. You may want to consider using the rust library for seed
 * generation and derivation.
 */
export class UnlockedSeedBundle {
  // the secret buffer is stored here
  #secret

  /**
   * the base64 encoded public key associated with this seed
   *
   * @instance
   * @type {string}
   */
  signPubKey

  /**
   * any app / user data to provide context for this particular seed
   *
   * @instance
   * @type {object}
   */
  appData = {}

  /**
   * You should not use this constructor directly.
   * Use one of:
   *  - `UnlockedKeyBundle.newRandom(appData)`
   *  - `UnlockedKeyBundle.fromLocked(encodedBytes)`
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {PrivSecretBuf} - parseSecret(Uint8Array)
   * @param {object} - appData to associate with bundle
   */
  constructor (secret, appData) {
    checkSodiumReady()

    if (!(secret instanceof PrivSecretBuf)) {
      throw new Error("invalid inner type. use 'newRandom()' or 'fromLocked()'")
    }

    this.#secret = secret
    Object.defineProperty(this, 'signPubKey', {
      value: secret.deriveSignPubKey(),
      writable: false
    })
    if (appData) {
      this.appData = appData
    }
  }

  /**
   * Construct a new completely random root seed with given app / user data.
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {object} - appData to associate with bundle
   */
  static newRandom (appData) {
    checkSodiumReady()
    const secret = parseSecret(_sodium.randombytes_buf(32))
    return new UnlockedSeedBundle(secret, appData)
  }

  /**
   * Extract the LockedSeedCipher list capable of decrypting
   * an UnlockedSeedBundle from an encrypted SeedBundle.
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {Uint8Array} - encoded bytes to decode / decrypt
   */
  static fromLocked (encodedBytes) {
    const decoded = msgpack.decode(encodedBytes)
    if (decoded.hcSeedBundleVer !== 0) {
      throw new Error('invalid hcSeedBundleVer, got: ' + decoded.hcSeedBundleVer)
    }

    const appData = msgpack.decode(decoded.appData)
    const finishUnlockCb = (secretSeed) => {
      return new UnlockedSeedBundle(secretSeed, appData)
    }

    const outList = []

    // somehow standard is failing to recognize the usage in the loop
    // eslint-disable-next-line no-unused-vars
    for (const seedCipher of decoded.seedCipherList) {
      if (seedCipher.type === 'pwHash') {
        outList.push(new LockedSeedCipherPwHash(finishUnlockCb, seedCipher.salt, seedCipher.seedCipherHeader, seedCipher.seedCipher))
      } else {
        throw new Error('unrecognized seedCipher type: ' + seedCipher.type)
      }
    }

    return outList
  }

  /**
   * You may change the app/user data with this function.
   *
   * @param {object} - appData to associate with bundle
   */
  setAppData (appData) {
    this.appData = appData
  }

  /**
   * Zero out the internal secret buffers.
   * WARNING: see class-level note about zeroing / secrets.
   */
  zero () {
    this.#secret.zero()
  }

  /**
   * Derive a subkey / seed from this seed bundle seed.
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {number} - derivation subkeyId
   * @param {object} - appData to associate with subseed bundle
   */
  derive (subkeyId, appData) {
    const next = this.#secret.derive(subkeyId)
    return new UnlockedSeedBundle(next, appData)
  }

  /**
   * Encrypt this seed into seed bundle bytes with given
   * seedCipherList - note, all seedCiphers will be zeroed.
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {SeedCipher[]} - list of seed ciphers to encrypt into the bundle
   */
  lock (seedCipherList) {
    if (!Array.isArray(seedCipherList)) {
      throw new Error('seedCipherList must be an array')
    }

    const encodedSeedCipherList = []

    // somehow standard is failing to recognize the usage in the loop
    // eslint-disable-next-line no-unused-vars
    for (const seedCipher of seedCipherList) {
      if (!(seedCipher instanceof SeedCipher)) {
        throw new Error('seedCipher must be instanceof SeedCipher')
      }
      encodedSeedCipherList.push(seedCipher.encryptSeed(this.#secret))
      seedCipher.zero()
    }

    const bundle = {
      hcSeedBundleVer: 0,
      seedCipherList: encodedSeedCipherList,
      appData: msgpack.encode(this.appData)
    }

    return msgpack.encode(bundle)
  }
}
