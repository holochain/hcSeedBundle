import {
  seedBundleReady,
  parseSecret,
  UnlockedSeedBundle,
  SeedCipherPwHash,
  SeedCipherSecurityQuestions,
  LockedSeedCipher,
  LockedSeedCipherPwHash,
  LockedSeedCipherSecurityQuestions,
} from "../index";
import fixtures, { type SuccessType, type UnlockType } from "./tests-assets/seed_bundle_test_fixtures";
import _sodium from "libsodium-wrappers-sumo";
import { describe, it, beforeAll, expect } from "bun:test";

async function generate(s: { unlock: UnlockType[] }): Promise<string> {
  const master = UnlockedSeedBundle.newRandom({});

  const createSeedCipher = (u: UnlockType) => {
    if (u.type === "pwHash") {
      const pw = new TextEncoder().encode(u.passphrase!);
      return new SeedCipherPwHash(parseSecret(pw), "minimum");
    }
    if (u.type === "securityQuestions") {
      const answerList = u.answerList!.map((answer) => parseSecret(new TextEncoder().encode(answer)));
      return new SeedCipherSecurityQuestions(u.questionList!, answerList, "minimum");
    }
    throw new Error("invalid SeedCipher: " + JSON.stringify(u));
  };

  const cList = s.unlock.map(createSeedCipher);
  const masterEncoded = master.lock(cList);

  return _sodium.to_base64(masterEncoded, _sodium.base64_variants.URLSAFE_NO_PADDING);
}

describe("SeedBundle Test Suite", () => {
  beforeAll(async () => {
    await _sodium.ready;

    await Promise.all(
      fixtures.success.map(async (fixt) => {
        if (!fixt.cipher) {
          throw new Error("required cipher, like: " + (await generate(fixt)));
        }

        fixt.cipher = _sodium.from_base64(fixt.cipher, _sodium.base64_variants.URLSAFE_NO_PADDING) as unknown as string;
      }),
    );
  });

  fixtures.success.forEach((fixt: SuccessType, fi: number) => {
    describe(`fixture-success-test-${fi}`, () => {
      it("unlock and derive", async () => {
        const cList = UnlockedSeedBundle.fromLocked(fixt.cipher as unknown as Uint8Array);
        expect(cList.length).toBe(fixt.unlock.length);

        const unlockSeedCipher = (unlock: UnlockType, seedCipher: LockedSeedCipher) => {
          if (unlock.type === "pwHash") {
            const pw = new TextEncoder().encode(unlock.passphrase!);
            return (seedCipher as LockedSeedCipherPwHash).unlock(parseSecret(pw));
          }
          if (unlock.type === "securityQuestions") {
            const answerList = unlock.answerList!.map((answer) => parseSecret(new TextEncoder().encode(answer)));
            expect(unlock.questionList).toEqual((seedCipher as LockedSeedCipherSecurityQuestions).getQuestionList());
            return (seedCipher as LockedSeedCipherSecurityQuestions).unlock(answerList);
          }
          throw new Error("invalid SeedCipher: " + seedCipher);
        };

        const sList = fixt.unlock.map((unlock, ui) => unlockSeedCipher(unlock, cList[ui]));

        sList.forEach((cmp) => {
          expect(_sodium.from_base64(fixt.signPubKey)).toStrictEqual(cmp.signPubKey);
        });

        Object.entries(fixt.derivations).forEach(([path, signPubKey]) => {
          let cur = sList[0];
          path.split("/").forEach((id) => {
            if (id !== "m") {
              cur = cur.derive(parseInt(id, 10));
            }
          });
          expect(_sodium.from_base64(signPubKey)).toStrictEqual(cur.signPubKey);
        });
      });
    });
  });

  it("subseed key !== parent", async () => {
    await seedBundleReady;

    const master = UnlockedSeedBundle.newRandom({
      bundleType: "master",
    });

    const deviceRoot = master.derive(68, {
      bundleType: "deviceRoot",
    });

    expect(master.signPubKey).not.toBe(deviceRoot.signPubKey);

    master.zero();
    deviceRoot.zero();
  });

  it("lock/unlock pwHash key equality", async () => {
    await seedBundleReady;

    const master = UnlockedSeedBundle.newRandom({
      bundleType: "master",
    });

    const pw1 = new TextEncoder().encode("test-passphrase");
    const masterEncoded = master.lock([new SeedCipherPwHash(parseSecret(pw1), "minimum")]);

    master.zero();

    const unlockCipherList = UnlockedSeedBundle.fromLocked(masterEncoded);

    const pw2 = new TextEncoder().encode("test-passphrase");
    const master2 = (unlockCipherList[0] as LockedSeedCipherPwHash).unlock(parseSecret(pw2));

    expect(master.signPubKey).toStrictEqual(master2.signPubKey);

    master2.zero();
  });

  it("lock/unlock securityQuestion key equality", async () => {
    await seedBundleReady;

    const master = UnlockedSeedBundle.newRandom({
      bundleType: "master",
    });

    const q1 = "What was the name of your first pet?";
    const q2 = "What was the model of your first car?";
    const q3 = "What are you most afraid of?";

    const a1 = new TextEncoder().encode("Fred  ");
    const a2 = new TextEncoder().encode(" PinTo");
    const a3 = new TextEncoder().encode("\tZoMbies");
    const masterEncoded = master.lock([
      new SeedCipherSecurityQuestions([q1, q2, q3], [parseSecret(a1), parseSecret(a2), parseSecret(a3)], "minimum"),
    ]);

    master.zero();

    const unlockCipherList = UnlockedSeedBundle.fromLocked(masterEncoded);

    expect([q1, q2, q3]).toEqual((unlockCipherList[0] as LockedSeedCipherSecurityQuestions).getQuestionList());

    const b1 = new TextEncoder().encode("FreD\n");
    const b2 = new TextEncoder().encode("PINTO");
    const b3 = new TextEncoder().encode("\t\tZombies");
    const master2 = (unlockCipherList[0] as LockedSeedCipherSecurityQuestions).unlock([
      parseSecret(b1),
      parseSecret(b2),
      parseSecret(b3),
    ]);

    expect(master.signPubKey).toStrictEqual(master2.signPubKey);

    master2.zero();
  });
});
