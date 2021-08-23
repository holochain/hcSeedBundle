import _sodium from 'libsodium-wrappers'
import msgpack from 'msgpack-lite'
import base64 from 'base64-js'

async function main() {
  const passphrase = (new TextEncoder()).encode('test-passphrase')

  const root = await UnlockedKeyBundle.newRandom({
    bundleType: 'root'
  })

  console.log('root', root)

  const locked = await root.lock(passphrase)
  console.log('locked', locked)

  const root2 = await UnlockedKeyBundle.fromLocked(locked, passphrase)
  console.log('root2', root2)

  const next = await root2.derive('hc-device', 3, {
    bundleType: 'device'
  })

  console.log('next', next)
}

/**
 * Represents a key bundle with access to secret seeds for derivation.
 *
 * WARNING: Before forgetting about an UnlockedKeyBundle instance, you
 * should probably call the `zero` function to clear the internal secret data.
 * HOWEVER, being javascript, there is no guarantee we haven't leaked
 * secret data. You may want to consider using the rust library for seed
 * generation and derivation.
 */
class UnlockedKeyBundle {
  // the "inner" bundle object is stored here
  #inner

  // any app / user data to provide context for this particular seed
  appData = {}

  // the base64 encoded public key associated with this seed
  seedPubKey

  /**
   * You should not use this constructor directly.
   * Use one of:
   *  - `UnlockedKeyBundle.newRandom(appData)`
   *  - `UnlockedKeyBundle.fromLocked(encodedBytes, passphrase)`
   * WARNING: see class-level note about zeroing / secrets.
   */
  constructor(inner, appData) {
    this.#inner = inner
    this.seedPubKey = inner.seedPubKey
    if (appData) {
      this.appData = appData
    }
  }

  /**
   * Construct a new completely random root seed with given app / user data.
   * WARNING: see class-level note about zeroing / secrets.
   */
  static async newRandom(appData) {
    return new UnlockedKeyBundle(await privGenBundleInnerRandom(), appData)
  }

  /**
   * Decrypt locked seed bundle bytes with given passphrase.
   * WARNING: see class-level note about zeroing / secrets.
   */
  static async fromLocked(encodedBytes, passphrase) {
    const { inner, appData } = await privGenBundleInnerFromLocked(encodedBytes, passphrase)
    return new UnlockedKeyBundle(inner, appData)
  }

  /**
   * You may change the app/user data with this function.
   */
  setAppData(appData) {
    this.appData = appData
  }

  /**
   * Zero out the internal secret buffers.
   * WARNING: see class-level note about zeroing / secrets.
   */
  zero() {
    this.#inner.zero()
  }

  /**
   * Encrypt this seed into key bundle bytes.
   * WARNING: see class-level note about zeroing / secrets.
   */
  async lock(passphrase) {
    return await this.#inner.lock(this.appData, passphrase)
  }

  /**
   * Derive a subkey / seed from this key bundle seed.
   * WARNING: see class-level note about zeroing / secrets.
   */
  async derive(context, index, appData) {
    const next = await this.#inner.derive(context, index)
    return new UnlockedKeyBundle(next, appData)
  }
}

/**
 * Generate an "inner" object where secret data is obscured by closures
 * as an extra layer of defense for accidental exposure by e.g. logging etc...
 */
async function privGenBundleInner(hideSalt, hideNonce, hideSeed) {
  await _sodium.ready

  const { publicKey, privateKey } = _sodium.crypto_sign_seed_keypair(hideSeed)
  _sodium.memzero(privateKey)
  const seedPubKey = base64.fromByteArray(publicKey)

  const cfg = {
    didZero: false,
  };

  // this function zeroes out our secret data
  const zero = () => {
    _sodium.memzero(hideSalt)
    _sodium.memzero(hideNonce)
    _sodium.memzero(hideSeed)
    cfg.didZero = true
  }

  // encrypt a "locked" outer bundle with given passphrase
  const lock = async (appData, passphrase) => {
    if (!(passphrase instanceof Uint8Array)) {
      throw new Error("passphrase must be a Uint8Array")
    }

    if (cfg.didZero) {
      throw new Error("This bundle has been zeroed, cannot lock")
    }

    // random outer salt
    const salt = _sodium.randombytes_buf(16)

    // generate secret from pwhash
    const secret = _sodium.crypto_pwhash(
      32,
      passphrase,
      salt,
      _sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      _sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      _sodium.crypto_pwhash_ALG_ARGON2ID13
    )

    // initialize encryption
    const { state, header } = _sodium
      .crypto_secretstream_xchacha20poly1305_init_push(secret)

    _sodium.memzero(secret)

    // encode our inner secret data
    const encoded = msgpack.encode({
      secretSalt: hideSalt,
      secretNonce: hideNonce,
      secretSeed: hideSeed,
    })

    // encrypt our inner secret data
    const cipher = _sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      encoded,
      null,
      _sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    )

    // zero out the secret encoded data buffer
    _sodium.memzero(encoded)

    // build up the outer bundle format
    const bundle = {
      hcKeyBundleVer: 0,
      appData: msgpack.encode(appData),
      salt,
      header,
      cipher,
    }

    // encode and return the locked outer bundle
    return msgpack.encode(bundle)
  }

  // derive a subkey with given context / index
  const derive = async (context, index) => {
    if (cfg.didZero) {
      throw new Error("This bundle has been zeroed, cannot derive")
    }

    const sodiumContext = _sodium.from_string(context)

    // we calculate salt from
    //  - 16 bytes parent salt
    //  - 8 bytes index u64_le
    //  - context bytes
    const saltInput = new Uint8Array(16 + 8 + sodiumContext.length)

    // add the salt
    saltInput.set(hideSalt)

    // add the index
    const indexBuf = new DataView(new ArrayBuffer(8));
    indexBuf.setBigUint64(0, BigInt(index), true) // set little-endian
    saltInput.set(indexBuf.buffer, 16)
    _sodium.memzero(new Uint8Array(indexBuf.buffer))

    // add the context
    saltInput.set(sodiumContext, 16 + 8)

    // calclulate the blake2b16 of the above
    const calcSalt = _sodium.crypto_generichash(16, saltInput)

    _sodium.memzero(saltInput)

    // we build the passphrase from
    //  - 16 bytes parent nonce
    //  - 32 bytes parent seed
    const calcPassphrase = new Uint8Array(16 + 32)

    // add the nonce
    calcPassphrase.set(hideNonce)

    // add the seed
    calcPassphrase.set(hideSeed, 16)

    // calculate the derived hash
    const next = _sodium.crypto_pwhash(
      64,
      calcPassphrase,
      calcSalt,
      _sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      _sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      _sodium.crypto_pwhash_ALG_ARGON2ID13
    )

    _sodium.memzero(calcSalt)
    _sodium.memzero(calcPassphrase)

    // generate the derived inner bundle object
    const nextInner = await privGenBundleInner(
      next.subarray(0, 16),
      next.subarray(16, 32),
      next.subarray(32)
    )

    _sodium.memzero(next)

    return nextInner
  }

  const out = Object.create(null)

  Object.defineProperties(out, {
    'seedPubKey': { value: seedPubKey },
    'zero': { value: zero },
    'lock': { value: lock },
    'derive': { value: derive },
  })

  Object.freeze(out)

  return out
}

/**
 * Generate a pure entropy random "inner" object that is a root seed.
 */
async function privGenBundleInnerRandom() {
  await _sodium.ready

  // all components are pure-random entropy
  const salt = _sodium.randombytes_buf(16)
  const nonce = _sodium.randombytes_buf(16)
  const seed = _sodium.randombytes_buf(32)

  // build/return the inner bundle
  return await privGenBundleInner(salt, nonce, seed)
}

/**
 * Unlock a locked bundle
 */
async function privGenBundleInnerFromLocked(bundle, passphrase) {
  await _sodium.ready

  if (!(bundle instanceof Uint8Array)) {
    throw new Error("bundle must be a Uint8Array")
  }
  if (!(passphrase instanceof Uint8Array)) {
    throw new Error("passphrase must be a Uint8Array")
  }

  // parse the outer bundle
  const bundleParsed = msgpack.decode(bundle)

  // calculate the secret from the salt / passphrase
  const secret = _sodium.crypto_pwhash(
    32,
    passphrase,
    bundleParsed.salt,
    _sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    _sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    _sodium.crypto_pwhash_ALG_ARGON2ID13
  )

  // initialize decryption
  const state = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(
    bundleParsed.header,
    secret
  )

  _sodium.memzero(secret)

  // finalize decryption
  const res = _sodium.crypto_secretstream_xchacha20poly1305_pull(state, bundleParsed.cipher)
  if (!res) {
    throw new Error('failed to decrypt bundle')
  }
  const { message, tag } = res

  // decode the inner bundle
  const decoded = msgpack.decode(message)

  // generate the inner bundle object
  const inner = await privGenBundleInner(decoded.secretSalt, decoded.secretNonce, decoded.secretSeed)

  // return the decoded components
  return { inner, appData: msgpack.decode(bundleParsed.appData) }
}

await main()
