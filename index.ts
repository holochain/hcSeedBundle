import _sodium from "libsodium-wrappers-sumo";
import { encode, decode } from "@msgpack/msgpack";

interface SodiumConfig {
  sodiumReady: boolean;
}

const _sodiumCfg: SodiumConfig = {
  sodiumReady: false,
};

export const seedBundleReady: Promise<void> = _sodium.ready.then(() => {
  _sodiumCfg.sodiumReady = true;
});

function checkSodiumReady(): void {
  if (!_sodiumCfg.sodiumReady) {
    throw new Error('seedBundle library not ready. Await "seedBundleReady" first.');
  }
}

export class PrivSecretBuf {
  private secret: Uint8Array;
  private cfg: { didZero: boolean };

  constructor(secret: Uint8Array) {
    checkSodiumReady();

    if (!(secret instanceof Uint8Array)) {
      throw new Error("secret must be a Uint8Array");
    }

    if (_sodium.is_zero(secret)) {
      throw new Error("secret cannot be a zeroed Uint8Array");
    }

    this.secret = secret;
    this.cfg = { didZero: false };

    Object.freeze(this);
  }

  get(): Uint8Array {
    if (this.cfg.didZero) {
      throw new Error("cannot access secret, already zeroed");
    }
    return this.secret;
  }

  zero(): void {
    _sodium.memzero(this.secret);
    this.cfg.didZero = true;
  }

  deriveSignPubKey(): Uint8Array {
    if (this.cfg.didZero) throw new Error("cannot access secret, already zeroed");
    if (this.secret.length !== 32) {
      throw new Error("can only derive secrets of length 32");
    }

    const { publicKey, privateKey } = _sodium.crypto_sign_seed_keypair(this.secret);
    _sodium.memzero(privateKey);
    return publicKey;
  }

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

export function parseSecret(secret: Uint8Array): PrivSecretBuf {
  checkSodiumReady();
  return new PrivSecretBuf(secret);
}

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

export abstract class SeedCipher {
  constructor() {
    checkSodiumReady();
  }

  zero(): void {
    throw new Error("SeedCipher.zero is not callable on base class");
  }

  abstract encryptSeed(secretSeed: PrivSecretBuf): object;
}

export class LockedSeedCipher {
  private finishUnlockCb: (secretSeed: PrivSecretBuf) => UnlockedSeedBundle;

  constructor(finishUnlockCb: (secretSeed: PrivSecretBuf) => UnlockedSeedBundle) {
    checkSodiumReady();
    this.finishUnlockCb = finishUnlockCb;
  }

  finishUnlock(secretSeed: PrivSecretBuf): UnlockedSeedBundle {
    return this.finishUnlockCb(secretSeed);
  }
}

export class SeedCipherPwHash extends SeedCipher {
  private passphrase: PrivSecretBuf;
  private limitName?: string;

  constructor(passphrase: PrivSecretBuf, limitName?: string) {
    super();
    if (!(passphrase instanceof PrivSecretBuf)) {
      throw new Error("passphrase required, construct with parseSecret()");
    }
    this.passphrase = passphrase;
    this.limitName = limitName;
  }

  zero(): void {
    this.passphrase.zero();
  }

  encryptSeed(secretSeed: PrivSecretBuf): object {
    if (!(secretSeed instanceof PrivSecretBuf)) {
      throw new Error("secretSeed must be an internal secret buffer");
    }

    const pwHash = _sodium.crypto_generichash(64, this.passphrase.get());
    const salt = _sodium.randombytes_buf(16);
    const { opsLimit, memLimit } = privTxLimits(this.limitName || "moderate");

    const secret = _sodium.crypto_pwhash(32, pwHash, salt, opsLimit, memLimit, _sodium.crypto_pwhash_ALG_ARGON2ID13);

    _sodium.memzero(pwHash);

    const { state, header } = _sodium.crypto_secretstream_xchacha20poly1305_init_push(secret);
    _sodium.memzero(secret);

    const cipher = _sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      secretSeed.get(),
      null,
      _sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    );

    return ["pw", salt, memLimit, opsLimit, header, cipher];
  }
}

export class SeedCipherSecurityQuestions extends SeedCipher {
  private questionList: string[];
  private answerBlob: PrivSecretBuf;
  private limitName?: string;

  constructor(questions: string[], answers: PrivSecretBuf[], limitName?: string) {
    super();
    if (!Array.isArray(questions) || !Array.isArray(answers) || questions.length !== 3 || answers.length !== 3) {
      throw new Error("require 3 questions and 3 answers");
    }

    this.questionList = questions;
    this.answerBlob = privNormalizeSecurityAnswers(answers);
    this.limitName = limitName;
  }

  zero(): void {
    this.answerBlob.zero();
  }

  encryptSeed(secretSeed: PrivSecretBuf): object {
    if (!(secretSeed instanceof PrivSecretBuf)) {
      throw new Error("secretSeed must be an internal secret buffer");
    }

    const pwHash = _sodium.crypto_generichash(64, this.answerBlob.get());
    const salt = _sodium.randombytes_buf(16);
    const { opsLimit, memLimit } = privTxLimits(this.limitName || "moderate");

    const secret = _sodium.crypto_pwhash(32, pwHash, salt, opsLimit, memLimit, _sodium.crypto_pwhash_ALG_ARGON2ID13);

    _sodium.memzero(pwHash);

    const { state, header } = _sodium.crypto_secretstream_xchacha20poly1305_init_push(secret);
    _sodium.memzero(secret);

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

export class LockedSeedCipherPwHash extends LockedSeedCipher {
  private salt: Uint8Array;
  private memLimit: number;
  private opsLimit: number;
  private header: Uint8Array;
  private cipher: Uint8Array;

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

export class LockedSeedCipherSecurityQuestions extends LockedSeedCipher {
  private salt: Uint8Array;
  private memLimit: number;
  private opsLimit: number;
  private questionList: string[];
  private header: Uint8Array;
  private cipher: Uint8Array;

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

  getQuestionList(): string[] {
    return this.questionList.slice();
  }

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

export class UnlockedSeedBundle {
  private secret: PrivSecretBuf;
  public signPubKey: Uint8Array;
  public appData: object = {};

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

  static newRandom(appData: object): UnlockedSeedBundle {
    checkSodiumReady();
    const secret = parseSecret(_sodium.randombytes_buf(32));
    return new UnlockedSeedBundle(secret, appData);
  }

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

  derive(subkeyId: number, appData?: object): UnlockedSeedBundle {
    const derivedSecret = this.secret.derive(subkeyId);
    return new UnlockedSeedBundle(derivedSecret, appData);
  }

  sign(message: Uint8Array | string): Uint8Array {
    return this.secret.sign(message);
  }

  zero(): void {
    this.secret.zero();
  }
}

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
