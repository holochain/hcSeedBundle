import * as hcSeedBundle from "../index.js"
import _sodium from "libsodium-wrappers"

describe.only("Example tests for david", () => {
  it("Locking (encrypting) a SeedBundle", async () => {
    // await library functions ready to call
    await hcSeedBundle.seedBundleReady

    /** Generate Master Seed */
    let MASTER_PASSPHRASE = "test-passphrase"
    // we need the passphrase as a Uint8Array
    const pw = new TextEncoder().encode(MASTER_PASSPHRASE)
    // generate a new pure entropy master seed
    const master = hcSeedBundle.UnlockedSeedBundle.newRandom({
      bundle_type: "master",
    })
    master.setAppData({
      generate_by: "keymanager-v1.0",
    })
    const encodedBytes = master.lock([
      new hcSeedBundle.SeedCipherPwHash(
        hcSeedBundle.parseSecret(pw),
        "minimum"
      ),
    ])

    console.log("Created master seed: ", master.signPubKey)

    // This is the format we have been using in holo to be stored in a file
    // const seedBlob = new Blob(
    //   [
    //     _sodium.to_base64(
    //       encodedBytes,
    //       _sodium.base64_variants.URLSAFE_NO_PADDING
    //     ),
    //   ],
    //   { type: "text/plain" }
    // )

    // -- if you want to regenerate for (decrypting) below:
    console.log(Buffer.from(encodedBytes).toString("base64"))
    /**Generate Revocation Keys */
    // We can decide that index 0 is the revocationRoot Path
    const revocationDerivationPath = 0
    await derive(
      revocationDerivationPath,
      "revocationRoot",
      new TextEncoder().encode("passphrase")
    )

    /** Generate Device Seed */
    // We can use the device number as the derivation path
    let deviceNumber = 1
    let device_seed = await derive(
      deviceNumber,
      "deviceRoot",
      new TextEncoder().encode("passphrase")
    )

    let app_key_1 = device_seed.derive(0);
    let app_key_2 = device_seed.derive(1);
    let app_key_3 = device_seed.derive(2);
    console.log(`App signPubkey: ${app_key_1.signPubKey}`)
    console.log(`App signPubkey: ${app_key_2.signPubKey}`)
    console.log(`App signPubkey: ${app_key_3.signPubKey}`)
    
    async function derive(derivationPath, bundleType, passphrase) {
      // generate device bundle
      // derive a device root seed from the master
      const root = master.derive(derivationPath, {
        bundle_type: bundleType,
      })
      root.setAppData({
        device_number: derivationPath,
        generate_by: "keymanager-v1.0",
      })
      // encrypts it with password: pass
      let pubKey = root.signPubKey
      let encodedBytes = root.lock([
        new hcSeedBundle.SeedCipherPwHash(
          hcSeedBundle.parseSecret(passphrase),
          "minimum"
        ),
      ])

      console.log("Created from master seed: ", master.signPubKey)
      console.log(
        `DerivationPath ${derivationPath}: ${Buffer.from(encodedBytes).toString(
          "base64"
        )}`
      )
      return root
    }

    // clear our secrets
    master.zero()
  })

  //   it("Locking (encrypting) a SeedBundle with Security Questions", async () => {
  //     // await library functions ready to call
  //     await hcSeedBundle.seedBundleReady

  //     // generate a new pure entropy master seed
  //     const master = hcSeedBundle.UnlockedSeedBundle.newRandom({
  //       bundleType: "master",
  //     })

  //     // we need the answers as a Uint8Arrays
  //     const pw = (pw) => hcSeedBundle.parseSecret(new TextEncoder().encode(pw))

  //     const encodedBytes = master.lock([
  //       new hcSeedBundle.SeedCipherSecurityQuestions(
  //         ["Favorite Color?", "Favorite Hair?", "Favorite Food?"],
  //         [pw("blue"), pw("big"), pw("begal")],
  //         "minimum"
  //       ),
  //     ])

  //     // clear our secrets
  //     master.zero()
  //   })
})
