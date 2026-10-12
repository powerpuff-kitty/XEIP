// Compatibility entrypoint: shared implementation lives in packages/identity.
export * from "../packages/identity/signed-envelope.mjs";
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { encodeKeyId, entityUrn } from "../packages/identity/key-id.mjs";
import { verifySignedEnvelope } from "../packages/identity/signed-envelope.mjs";

function printUsage() {
  return (
    "usage:\n" +
    "  node tools/signed-envelope.mjs verify <file.json>\n" +
    "  node tools/signed-envelope.mjs keygen\n"
  );
}

function main(argv) {
  const [command, argument] = argv;
  if (command === "verify") {
    if (argument === undefined) {
      process.stderr.write(printUsage());
      process.exitCode = 1;
      return;
    }
    try {
      const result = verifySignedEnvelope(readFileSync(argument, "utf8"));
      process.stdout.write(JSON.stringify(result) + "\n");
      if (!result.valid) process.exitCode = 1;
    } catch (error) {
      process.stderr.write(`error: ${error.message}\n`);
      process.exitCode = 1;
    }
    return;
  }
  if (command === "keygen") {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const seed = Buffer.from(privateKey.export({ format: "jwk" }).d, "base64url");
    const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    const kid = encodeKeyId(raw);
    process.stdout.write(
      JSON.stringify({
        seedHex: seed.toString("hex"),
        publicKeyHex: raw.toString("hex"),
        keyId: kid,
        entityUrn: entityUrn(kid),
      }) + "\n",
    );
    return;
  }
  process.stderr.write(printUsage());
  process.exitCode = 1;
}

// Run only when invoked directly, so importing the module in tests is silent.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
