import dts from "bun-plugin-dts";

await Bun.build({
  entrypoints: ["./index.ts"],
  outdir: "./out",
  plugins: [dts()],
  external: ["libsodium-wrappers-sumo", "react"],
});
