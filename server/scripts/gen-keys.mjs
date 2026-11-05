// Generates the two server secrets. Run once, store the output in .env (chmod 600).
// ARBITER_PUBLIC_KEY must also be pasted into index.html (CONFIG.ARBITER_PUBKEY)
// so clients refuse escrows signed by any other key.
import { randomBytes } from "node:crypto";
import { arbiterKeyFromSeed } from "../src/escrow.js";

const seed = randomBytes(32).toString("hex");
const { publicKeyHex } = arbiterKeyFromSeed(seed);
console.log(`ARBITER_SECRET=${seed}`);
console.log(`DATA_KEY=${randomBytes(32).toString("hex")}`);
console.log(`# ARBITER_PUBLIC_KEY=${publicKeyHex}   <- put into index.html CONFIG.ARBITER_PUBKEY`);
