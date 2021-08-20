import _sodium from 'libsodium-wrappers'
import msgpack from 'msgpack-lite'

var sodium = _sodium

function randRoot(passphrase) {
  const secretSalt = sodium.randombytes_buf(16)
  const secretSeed = sodium.randombytes_buf(32)
  const additionalContext = msgpack.encode({
    bundleType: 'root'
  })
  const inner = { secretSalt, secretSeed, additionalContext }
  const innerEnc = msgpack.encode(inner)

  const salt = sodium.randombytes_buf(16)

  const secret = sodium.crypto_pwhash(
    32,
    sodium.from_string(passphrase),
    salt,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  )

  const { state, header } = sodium
    .crypto_secretstream_xchacha20poly1305_init_push(secret)

  const cipher = sodium.crypto_secretstream_xchacha20poly1305_push(
    state,
    innerEnc,
    null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
  )

  const bundle = {
    hcKeyBundleVer: 0,
    salt,
    header,
    cipher,
  }

  return msgpack.encode(bundle)
}

function unlockBundle(bundle, passphrase) {
  const bundleParsed = msgpack.decode(bundle)

  const secret = sodium.crypto_pwhash(
    32,
    sodium.from_string(passphrase),
    bundleParsed.salt,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  )

  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
    bundleParsed.header,
    secret
  )

  const { message, tag } = sodium.crypto_secretstream_xchacha20poly1305_pull(state, bundleParsed.cipher)

  const inner = msgpack.decode(message)
  inner.additionalContext = msgpack.decode(inner.additionalContext)

  return inner
}

function derive(parentBundle, deriveSpec) {
  let cur = parentBundle
  for (const [context, index] of deriveSpec) {
    console.log('derive by [', context, ',', index, ']')

    const sodiumContext = sodium.from_string(context)

    const passphrase = new Uint8Array(32 + 8 + sodiumContext.length)
    passphrase.set(cur.secretSeed)
    const indexBuf = new BigUint64Array(1)
    indexBuf[0] = BigInt(index)
    passphrase.set(indexBuf.buffer, 32)
    passphrase.set(sodiumContext, 32 + 8)

    const salt = cur.secretSalt

    const next = sodium.crypto_pwhash(
      48,
      passphrase,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    )

    cur = {
      secretSalt: next.subarray(0, 16),
      secretSeed: next.subarray(16),
      additionalContext: {}
    }
    console.log(cur)
  }

  return cur
}

async function main() {
  console.log('awaiting sodium ready..')
  await _sodium.ready
  console.log('sodium ready.')
  sodium = _sodium

  if (sodium.crypto_pwhash_ALG_DEFAULT !== sodium.crypto_pwhash_ALG_ARGON2ID13) {
    throw new Error('invalid default pwhash alg: ' + sodium.crypto_pwhash_ALG_DEFAULT)
  }

  console.log('generating random root bundle..')
  const root = randRoot('test-passphrase')
  console.log('generated random root bundle: ', root)

  console.log('unlocking random root bundle..')
  const unlockedRoot = unlockBundle(root, 'test-passphrase')
  console.log('unlocked: ', unlockedRoot)

  const next = derive(unlockedRoot, [
    ['hc-device', 3],
    ['hc-app', 42]
  ])
  console.log('got derived: ', next)

  //console.log(JSON.stringify(Object.keys(sodium), null, 2))
}

await main()
