// Using the relative path to the actual JS file inside node_modules
// because we are running directly in the browser without a bundler.
import init, {
  PubkeyValidityProofData,
  ElGamalKeypair,
} from "./node_modules/@solana/zk-sdk/dist/web/index.js";

const statusElement = document.getElementById("status");
const logsElement = document.getElementById("logs");

function log(message) {
  console.log(message);
  logsElement.textContent += message + "\n";
}

function setStatus(statusClass, message) {
  statusElement.className = statusClass;
  statusElement.textContent = message;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

async function runTests() {
  try {
    log("Initializing Wasm module...");
    await init();
    log("Wasm module initialized.");
    setStatus("running", "Running tests...");

    // the rest is identical to the other integration tests
    const keypair = new ElGamalKeypair();
    assert(keypair, "Keypair creation failed");
    log("✅ Keypair generated.");

    const proof = new PubkeyValidityProofData(keypair);
    assert(proof, "Proof creation failed");
    log("✅ Proof generated.");

    proof.verify();
    log("✅ Proof verified.");

    setStatus("success", "✅ Web integration tests passed!");
    log("Tests passed!");
  } catch (error) {
    console.error("❌ Web integration tests failed:", error);
    setStatus("failure", "❌ Web integration tests failed. Check logs.");
    log("Error: " + error.message);
    log(error.stack);
  }
}

runTests();
