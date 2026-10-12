// Compatibility entrypoint: shared implementation lives in packages/identity.
export * from "../packages/identity/key-id.mjs";
import { pathToFileURL } from "node:url";
import { encodeKeyId, parsePublicKey, entityUrn, deviceUrn } from "../packages/identity/key-id.mjs";

function main(argv) {
  const [input] = argv;
  if (input === undefined) {
    process.stderr.write(
      "usage: node tools/derive-keyid.mjs <32-byte-ed25519-public-key (hex or base64url)>\n",
    );
    process.exitCode = 1;
    return;
  }
  try {
    const keyId = encodeKeyId(parsePublicKey(input));
    const output = {
      keyId,
      entityUrn: entityUrn(keyId),
      deviceUrn: deviceUrn(keyId),
    };
    process.stdout.write(JSON.stringify(output) + "\n");
  } catch (error) {
    process.stderr.write(`error: ${error.message}\n`);
    process.exitCode = 1;
  }
}

// Run only when invoked directly, so importing the module in tests is silent.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
