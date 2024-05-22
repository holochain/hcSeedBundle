import _sodium from "libsodium-wrappers-sumo";
import { encode, decode } from "@msgpack/msgpack";

/**
 * Configuration object for Sodium library readiness.
 */
interface SodiumConfig {
  sodiumReady: boolean;
}

const _sodiumCfg: SodiumConfig = {
  sodiumReady: false,
};

/**
 * Await this promise once before calling functions in this library.
 * @type {Promise<void>}
 */
export const seedBundleReady: Promise<void> = _sodium.ready.then(() => {
  _sodiumCfg.sodiumReady = true;
});

/**
 * Internal helper for ensuring the Sodium library is ready.
 * @throws {Error} Will throw an error if the Sodium library is not ready.
 */
function checkSodiumReady(): void {
  if (!_sodiumCfg.sodiumReady) {
    throw new Error('seedBundle library not ready. Await "seedBundleReady" first.');
  }
}

/**
 * Helper class that makes securing secrets easier by hiding them
 * in closures as additional protection against accidental exposure
 * via debugging, etc.
 * Note, when done with this secret, call `zero()` to clear the memory,
 * but be warned that this is JavaScript, and that is no guarantee
 * against exposure.
 */
export class PrivSecretBuf {
  private secret: Uint8Array;
  private cfg: { didZero: boolean };

  /**
   * Creates an instance of PrivSecretBuf.
   * @param {Uint8Array} secret the secret as a Uint8Array.
   * @throws {Error} Will throw an error if the secret is not a Uint8Array or is zeroed.
   */
  constructor(secret: Uint8Array) {
    checkSodiumReady();

    if (!(secret instanceof Uint8Array)) {
      throw new Error("secret must be a Uint8Array");
    }

    if (_sodium.is_zero(secret)) {
      throw new Error("secret cannot be a zeroed Uint8Array");
    }

    // setup some config to track our zero status
    this.secret = secret;
    this.cfg = { didZero: false };

    Object.freeze(this);
  }

  /**
   * Gets the secret.
   * @returns {Uint8Array} the secret as a Uint8Array.
   * @throws {Error} Will throw an error if the secret has already been zeroed.
   */
  get(): Uint8Array {
    if (this.cfg.didZero) {
      throw new Error("cannot access secret, already zeroed");
    }
    return this.secret;
  }

  /**
   * Zeroes the secret.
   */
  zero(): void {
    _sodium.memzero(this.secret);
    this.cfg.didZero = true;
  }

  /**
   * Derives a signing public key from the secret.
   * @returns {Uint8Array} the derived public key as a Uint8Array.
   * @throws {Error} Will throw an error if the secret has already been zeroed or is not of length 32.
   */
  deriveSignPubKey(): Uint8Array {
    if (this.cfg.didZero) throw new Error("cannot access secret, already zeroed");
    if (this.secret.length !== 32) {
      throw new Error("can only derive secrets of length 32");
    }

    const { publicKey, privateKey } = _sodium.crypto_sign_seed_keypair(this.secret);
    _sodium.memzero(privateKey);
    return publicKey;
  }

  /**
   * Signs a message with the secret.
   * @param {Uint8Array | string} message the message to sign, either as a Uint8Array or a string.
   * @returns {Uint8Array} the signature as a Uint8Array.
   * @throws {Error} Will throw an error if the secret has already been zeroed or is not of length 32.
   */
  sign(message: Uint8Array | string): Uint8Array {
    if (this.cfg.didZero) {
      throw new Error("cannot access secret, already zeroed");
    }
    if (this.secret.length !== 32) {
      throw new Error("can only derive secrets of length 32");
    }
    const { privateKey } = _sodium.crypto_sign_seed_keypair(this.secret);
    const signature = _sodium.crypto_sign_detached(message, privateKey);
    _sodium.memzero(privateKey);
    return signature;
  }

  /**
   * Derives a new secret from the current secret.
   * @param {number} subkeyId the subkey ID to use for derivation.
   * @returns {PrivSecretBuf} a new instance of PrivSecretBuf with the derived secret.
   * @throws {Error} Will throw an error if the secret has already been zeroed or is not of length 32.
   */
  derive(subkeyId: number): PrivSecretBuf {
    if (this.cfg.didZero) {
      throw new Error("cannot access secret, already zeroed");
    }
    if (this.secret.length !== 32) {
      throw new Error("can only derive secrets of length 32");
    }
    const newSecret = _sodium.crypto_kdf_derive_from_key(32, subkeyId, "SeedBndl", this.secret);
    return new PrivSecretBuf(newSecret);
  }
}

/**
 * Ingest a Uint8Array as an internal secret buffer.
 * Note, this buffer will be zeroed internally.
 *
 * @param {Uint8Array} secret the secret to ingest.
 * @returns {PrivSecretBuf} an instance of PrivSecretBuf.
 */
export function parseSecret(secret: Uint8Array): PrivSecretBuf {
  checkSodiumReady();
  return new PrivSecretBuf(secret);
}

/**
 * Helper to translate limit names into values.
 *
 * @param {string} limitName the name of the limit ("minimum", "interactive", "sensitive", "moderate").
 * @returns {{opsLimit: number, memLimit: number}} an object containing the operation and memory limits.
 */
function privTxLimits(limitName: string): {
  opsLimit: number;
  memLimit: number;
} {
  let opsLimit = _sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  let memLimit = _sodium.crypto_pwhash_MEMLIMIT_MODERATE;

  switch (limitName) {
    case "minimum":
      opsLimit = _sodium.crypto_pwhash_OPSLIMIT_MIN;
      memLimit = _sodium.crypto_pwhash_MEMLIMIT_MIN;
      break;
    case "interactive":
      opsLimit = _sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
      memLimit = _sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
      break;
    case "sensitive":
      opsLimit = _sodium.crypto_pwhash_OPSLIMIT_SENSITIVE;
      memLimit = _sodium.crypto_pwhash_MEMLIMIT_SENSITIVE;
      break;
    case "moderate":
    default:
      break;
  }

  return { opsLimit, memLimit };
}

/**
 * Base class for concrete SeedCiphers.
 */
export abstract class SeedCipher {
  constructor() {
    checkSodiumReady();
  }

  /**
   * Zeroes the seed cipher.
   * @throws {Error} Will throw an error if called on the base class.
   */
  zero(): void {
    throw new Error("SeedCipher.zero is not callable on base class");
  }

  /**
   * Encrypts a secret seed.
   * @param {PrivSecretBuf} secretSeed the secret seed to encrypt.
   * @returns {object} the encrypted seed as an object.
   */
  abstract encryptSeed(secretSeed: PrivSecretBuf): object;
}

/**
 * Base class for unlocking an encrypted seed cipher.
 */
export class LockedSeedCipher {
  private finishUnlockCb: (secretSeed: PrivSecretBuf) => UnlockedSeedBundle;

  /**
   * Don't use this directly, use a sub-class.
   * @param {(secretSeed: PrivSecretBuf) => UnlockedSeedBundle} finishUnlockCb the callback to finish unlocking the seed.
   */
  constructor(finishUnlockCb: (secretSeed: PrivSecretBuf) => UnlockedSeedBundle) {
    checkSodiumReady();
    this.finishUnlockCb = finishUnlockCb;
  }

  /**
   * Once the secretSeed is decrypted, subclass instances will call this
   * to generate the actual UnlockedSeedBundle instance.
   *
   * @param {PrivSecretBuf} secretSeed the secret seed to unlock.
   * @returns {UnlockedSeedBundle} an instance of UnlockedSeedBundle.
   */
  finishUnlock(secretSeed: PrivSecretBuf): UnlockedSeedBundle {
    return this.finishUnlockCb(secretSeed);
  }
}

/**
 * SeedCipher locked by a password hash.
 */
export class SeedCipherPwHash extends SeedCipher {
  private passphrase: PrivSecretBuf;
  private limitName?: string;

  /**
   * Build this with
   * @param {PrivSecretBuf} passphrase the passphrase as a PrivSecretBuf.
   * @param {string} [limitName] optional limit name (['interactive', 'moderate' *default*, 'sensitive']).
   * @throws {Error} Will throw an error if the passphrase is not an instance of PrivSecretBuf.
   */
  constructor(passphrase: PrivSecretBuf, limitName?: string) {
    super();
    if (!(passphrase instanceof PrivSecretBuf)) {
      throw new Error("passphrase required, construct with parseSecret()");
    }
    this.passphrase = passphrase;
    this.limitName = limitName;
  }

  /**
   * Clear secret data.
   */
  zero(): void {
    this.passphrase.zero();
  }

  /**
   * Encrypt a secretSeed SeedCipher with this instance.
   * @param {PrivSecretBuf} secretSeed the secret seed to encrypt.
   * @returns {object} the encrypted seed as an object.
   * @throws {Error} Will throw an error if the secret seed is not an instance of PrivSecretBuf.
   */
  encryptSeed(secretSeed: PrivSecretBuf): object {
    if (!(secretSeed instanceof PrivSecretBuf)) {
      throw new Error("secretSeed must be an internal secret buffer");
    }

    const pwHash = _sodium.crypto_generichash(64, this.passphrase.get());
    const salt = _sodium.randombytes_buf(16);
    const { opsLimit, memLimit } = privTxLimits(this.limitName || "moderate");

    // generate secret from pwhash
    const secret = _sodium.crypto_pwhash(32, pwHash, salt, opsLimit, memLimit, _sodium.crypto_pwhash_ALG_ARGON2ID13);

    _sodium.memzero(pwHash);

    // initialize encryption
    const { state, header } = _sodium.crypto_secretstream_xchacha20poly1305_init_push(secret);
    _sodium.memzero(secret);

    // encrypt our inner secret data
    const cipher = _sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      secretSeed.get(),
      null,
      _sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    );

    return ["pw", salt, memLimit, opsLimit, header, cipher];
  }
}

/**
 * SeedCipher locked by three security question answers.
 */
export class SeedCipherSecurityQuestions extends SeedCipher {
  private questionList: string[];
  private answerBlob: PrivSecretBuf;
  private limitName?: string;

  /**
   * Build this with
   * @param {string[]} questions the list of security questions.
   * @param {PrivSecretBuf[]} answers the list of answers as PrivSecretBuf.
   * @param {string} [limitName] optional limit name (['interactive', 'moderate' *default*, 'sensitive']).
   * @throws {Error} Will throw an error if the questions or answers are not arrays of length 3.
   */
  constructor(questions: string[], answers: PrivSecretBuf[], limitName?: string) {
    super();
    if (!Array.isArray(questions) || !Array.isArray(answers) || questions.length !== 3 || answers.length !== 3) {
      throw new Error("require 3 questions and 3 answers");
    }

    this.questionList = questions;
    this.answerBlob = privNormalizeSecurityAnswers(answers);
    this.limitName = limitName;
  }

  /**
   * Clear secret data.
   */
  zero(): void {
    this.answerBlob.zero();
  }

  /**
   * Encrypt a secretSeed SeedCipher with this instance.
   * @param {PrivSecretBuf} secretSeed the secret seed to encrypt.
   * @returns {object} the encrypted seed as an object.
   * @throws {Error} Will throw an error if the secret seed is not an instance of PrivSecretBuf.
   */
  encryptSeed(secretSeed: PrivSecretBuf): object {
    if (!(secretSeed instanceof PrivSecretBuf)) {
      throw new Error("secretSeed must be an internal secret buffer");
    }

    const pwHash = _sodium.crypto_generichash(64, this.answerBlob.get());
    const salt = _sodium.randombytes_buf(16);
    const { opsLimit, memLimit } = privTxLimits(this.limitName || "moderate");

    // generate secret from pwhash
    const secret = _sodium.crypto_pwhash(32, pwHash, salt, opsLimit, memLimit, _sodium.crypto_pwhash_ALG_ARGON2ID13);

    _sodium.memzero(pwHash);

    // initialize encryption
    const { state, header } = _sodium.crypto_secretstream_xchacha20poly1305_init_push(secret);
    _sodium.memzero(secret);

    // encrypt our inner secret data
    const cipher = _sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      secretSeed.get(),
      null,
      _sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    );

    return [
      "qa",
      salt,
      memLimit,
      opsLimit,
      this.questionList[0],
      this.questionList[1],
      this.questionList[2],
      header,
      cipher,
    ];
  }
}
/**
 * Unlock a SeedCipher with a straightforward pwhashed passphrase.
 */
export class LockedSeedCipherPwHash extends LockedSeedCipher {
  private salt: Uint8Array;
  private memLimit: number;
  private opsLimit: number;
  private header: Uint8Array;
  private cipher: Uint8Array;

  /**
   * You won't use this directly, call UnlockedSeedBundle.fromLocked()
   * @param {(secretSeed: PrivSecretBuf) => UnlockedSeedBundle} finishUnlockCb - The callback to finish unlocking the seed.
   * @param {Uint8Array} salt - The salt used for password hashing.
   * @param {number} memLimit - The memory limit for password hashing.
   * @param {number} opsLimit - The operation limit for password hashing.
   * @param {Uint8Array} header - The header for the secret stream.
   * @param {Uint8Array} cipher - The cipher text.
   */
  constructor(
    finishUnlockCb: (secretSeed: PrivSecretBuf) => UnlockedSeedBundle,
    salt: Uint8Array,
    memLimit: number,
    opsLimit: number,
    header: Uint8Array,
    cipher: Uint8Array,
  ) {
    super(finishUnlockCb);
    this.salt = salt;
    this.memLimit = memLimit;
    this.opsLimit = opsLimit;
    this.header = header;
    this.cipher = cipher;
  }

  /**
   * Unlock to an UnlockedSeedBundle.
   * @param {PrivSecretBuf} passphrase - The passphrase as a PrivSecretBuf.
   * @returns {UnlockedSeedBundle} An instance of UnlockedSeedBundle.
   * @throws {Error} Will throw an error if the passphrase is not an instance of PrivSecretBuf.
   */
  unlock(passphrase: PrivSecretBuf): UnlockedSeedBundle {
    if (!(passphrase instanceof PrivSecretBuf)) {
      throw new Error("passphrase required, construct with parseSecret()");
    }

    const pwHash = _sodium.crypto_generichash(64, passphrase.get());
    passphrase.zero();

    const secret = _sodium.crypto_pwhash(
      32,
      pwHash,
      this.salt,
      this.opsLimit,
      this.memLimit,
      _sodium.crypto_pwhash_ALG_ARGON2ID13,
    );

    _sodium.memzero(pwHash);

    const state = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(this.header, secret);
    _sodium.memzero(secret);

    const res = _sodium.crypto_secretstream_xchacha20poly1305_pull(state, this.cipher);
    if (!res) {
      throw new Error("failed to decrypt bundle");
    }
    const { message } = res;

    return this.finishUnlock(parseSecret(message));
  }
}

/**
 * Unlock a SeedCipher with three security question answers.
 */
export class LockedSeedCipherSecurityQuestions extends LockedSeedCipher {
  private salt: Uint8Array;
  private memLimit: number;
  private opsLimit: number;
  private questionList: string[];
  private header: Uint8Array;
  private cipher: Uint8Array;

  /**
   * You won't use this directly, call UnlockedSeedBundle.fromLocked()
   *
   * @param {(secretSeed: PrivSecretBuf) => UnlockedSeedBundle} finishUnlockCb the callback to finish unlocking the seed.
   * @param {Uint8Array} salt the salt used for password hashing.
   * @param {number} memLimit the memory limit for password hashing.
   * @param {number} opsLimit the operation limit for password hashing.
   * @param {string[]} questionList the list of security questions.
   * @param {Uint8Array} header the header for the secret stream.
   * @param {Uint8Array} cipher the cipher text.
   */
  constructor(
    finishUnlockCb: (secretSeed: PrivSecretBuf) => UnlockedSeedBundle,
    salt: Uint8Array,
    memLimit: number,
    opsLimit: number,
    questionList: string[],
    header: Uint8Array,
    cipher: Uint8Array,
  ) {
    super(finishUnlockCb);
    this.salt = salt;
    this.memLimit = memLimit;
    this.opsLimit = opsLimit;
    this.questionList = questionList;
    this.header = header;
    this.cipher = cipher;
  }

  /**
   * List the security questions that should be answered.
   *
   * @returns {string[]} a copy of the list of security questions.
   */
  getQuestionList(): string[] {
    return this.questionList.slice();
  }

  /**
   * Unlock to an UnlockedSeedBundle.
   *
   * @param {PrivSecretBuf[]} answers the list of answers as PrivSecretBuf.
   * @returns {UnlockedSeedBundle} an instance of UnlockedSeedBundle.
   * @throws {Error} will throw an error if the answers are not an array of length 3.
   */
  unlock(answers: PrivSecretBuf[]): UnlockedSeedBundle {
    if (!Array.isArray(answers) || answers.length !== 3) {
      throw new Error("require 3 answers");
    }

    const answerBlob = privNormalizeSecurityAnswers(answers);
    const pwHash = _sodium.crypto_generichash(64, answerBlob.get());
    answerBlob.zero();

    const secret = _sodium.crypto_pwhash(
      32,
      pwHash,
      this.salt,
      this.opsLimit,
      this.memLimit,
      _sodium.crypto_pwhash_ALG_ARGON2ID13,
    );

    _sodium.memzero(pwHash);

    const state = _sodium.crypto_secretstream_xchacha20poly1305_init_pull(this.header, secret);
    _sodium.memzero(secret);

    const res = _sodium.crypto_secretstream_xchacha20poly1305_pull(state, this.cipher);
    if (!res) {
      throw new Error("failed to decrypt bundle");
    }
    const { message } = res;

    return this.finishUnlock(parseSecret(message));
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
  private secret: PrivSecretBuf;
  public signPubKey: Uint8Array;
  public appData: object = {};

  /**
   * You should not use this constructor directly.
   * Use one of:
   *  - `UnlockedKeyBundle.newRandom(appData)`
   *  - `UnlockedKeyBundle.fromLocked(encodedBytes)`
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {PrivSecretBuf} secret the secret as a PrivSecretBuf.
   * @param {object} [appData] optional application data.
   * @throws {Error} will throw an error if the secret is not an instance of PrivSecretBuf.
   */
  constructor(secret: PrivSecretBuf, appData?: object) {
    checkSodiumReady();

    if (!(secret instanceof PrivSecretBuf)) {
      throw new Error("invalid inner type. use 'newRandom()' or 'fromLocked()'");
    }

    this.secret = secret;
    this.signPubKey = secret.deriveSignPubKey();
    if (appData) {
      this.appData = appData;
    }
  }

  /**
   * Construct a new completely random root seed with given app / user data.
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {object} [appData] optional application data.
   * @returns {UnlockedSeedBundle} a new instance of UnlockedSeedBundle.
   */
  static newRandom(appData: object): UnlockedSeedBundle {
    checkSodiumReady();
    const secret = parseSecret(_sodium.randombytes_buf(32));
    return new UnlockedSeedBundle(secret, appData);
  }

  /**
   * Extract the LockedSeedCipher list capable of decrypting
   * an UnlockedSeedBundle from an encrypted SeedBundle.
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {Uint8Array} encodedBytes the encoded bytes representing the locked seed bundle.
   * @returns {LockedSeedCipher[]} an array of LockedSeedCipher instances.
   * @throws {Error} will throw an error if the encoded bytes are invalid.
   */
  static fromLocked(encodedBytes: Uint8Array): LockedSeedCipher[] {
    const decoded = decode(encodedBytes);
    if (!Array.isArray(decoded) || decoded[0] !== "hcsb0") {
      throw new Error("invalid bundle, got: " + JSON.stringify(decoded));
    }
    const decodeAppData = (data: unknown): object => {
      const decodedData = decode(data);
      return typeof decodedData === "object" && !Array.isArray(decodedData) && decodedData !== null ? decodedData : {};
    };

    const appData: object = decoded[2].length ? decodeAppData(decoded[2]) : {};
    const finishUnlockCb = (secretSeed: PrivSecretBuf) => {
      return new UnlockedSeedBundle(secretSeed, appData);
    };
    const outList: LockedSeedCipher[] = [];
    for (const seedCipher of decoded[1]) {
      if (seedCipher[0] === "pw") {
        const [_, salt, memLimit, opsLimit, header, cipher] = seedCipher;
        outList.push(new LockedSeedCipherPwHash(finishUnlockCb, salt, memLimit, opsLimit, header, cipher));
      } else if (seedCipher[0] === "qa") {
        const [_, salt, memLimit, opsLimit, q1, q2, q3, header, cipher] = seedCipher;
        outList.push(
          new LockedSeedCipherSecurityQuestions(finishUnlockCb, salt, memLimit, opsLimit, [q1, q2, q3], header, cipher),
        );
      } else {
        throw new Error("unrecognized seedCipher type: " + seedCipher[0]);
      }
    }

    return outList;
  }

  /**
   * Encrypt this seed into seed bundle bytes with given
   * seedCipherList - note, all seedCiphers will be zeroed.
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {SeedCipher[]} seedCipherList an array of SeedCipher instances.
   * @returns {Uint8Array} the encoded locked seed bundle as a Uint8Array.
   * @throws {Error} will throw an error if the seedCipherList is not an array or contains invalid elements.
   */
  lock(seedCipherList: SeedCipher[]): Uint8Array {
    if (!Array.isArray(seedCipherList)) {
      throw new Error("seedCipherList must be an array");
    }

    const encodedSeedCipherList: object[] = [];

    for (const seedCipher of seedCipherList) {
      if (!(seedCipher instanceof SeedCipher)) {
        throw new Error("seedCipher must be instanceof SeedCipher");
      }
      encodedSeedCipherList.push(seedCipher.encryptSeed(this.secret));
      seedCipher.zero();
    }

    const bundle = ["hcsb0", encodedSeedCipherList, encode(this.appData)];

    return encode(bundle);
  }

  /**
   * Derive a subkey / seed from this seed bundle seed.
   * WARNING: see class-level note about zeroing / secrets.
   *
   * @param {number} subkeyId the subkey ID for derivation.
   * @param {object} [appData] optional application data.
   * @returns {UnlockedSeedBundle} a new instance of UnlockedSeedBundle.
   */
  derive(subkeyId: number, appData?: object): UnlockedSeedBundle {
    const derivedSecret = this.secret.derive(subkeyId);
    return new UnlockedSeedBundle(derivedSecret, appData);
  }

  /**
   * Signs a message using the secret.
   *
   * @param {Uint8Array | string} message the message to sign, either as a Uint8Array or a string.
   * @returns {Uint8Array} the signature as a Uint8Array.
   */
  sign(message: Uint8Array | string): Uint8Array {
    return this.secret.sign(message);
  }

  /**
   * Zero out the internal secret buffers.
   * WARNING: see class-level note about zeroing / secrets.
   */
  zero(): void {
    this.secret.zero();
  }
}

/**
 * Normalizes security answers by converting them to lowercase and trimming whitespace.
 *
 * @param {PrivSecretBuf[]} answers an array of PrivSecretBuf instances representing the answers.
 * @returns {PrivSecretBuf} a PrivSecretBuf instance containing the normalized answers.
 * @throws {Error} will throw an error if any answer is not an instance of PrivSecretBuf.
 */
function privNormalizeSecurityAnswers(answers: PrivSecretBuf[]): PrivSecretBuf {
  for (const a of answers) {
    if (!(a instanceof PrivSecretBuf)) {
      throw new Error("answer must be construct with parseSecret()");
    }
  }

  for (let ai = 0; ai < answers.length; ++ai) {
    const s = new TextDecoder().decode(answers[ai].get());
    answers[ai].zero();
    answers[ai] = parseSecret(new TextEncoder().encode(s.toLowerCase().trim()));
  }
  const total = answers[0].get().length + answers[1].get().length + answers[2].get().length;

  const answerBlob = new Uint8Array(total);
  answerBlob.set(answers[0].get());
  answerBlob.set(answers[1].get(), answers[0].get().length);
  answerBlob.set(answers[2].get(), answers[0].get().length + answers[1].get().length);

  _sodium.memzero(answers[0].get());
  _sodium.memzero(answers[1].get());
  _sodium.memzero(answers[2].get());

  return parseSecret(answerBlob);
}
