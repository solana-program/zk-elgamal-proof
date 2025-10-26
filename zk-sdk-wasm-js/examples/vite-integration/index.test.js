import {
  PubkeyValidityProofData,
  ElGamalKeypair,
} from "@solana/zk-sdk/bundler";

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
  log("--- Running Bundler (Vite) integration tests ---");

  try {
    log("Wasm module initialized (handled by Vite).");
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

    setStatus("success", "✅ Bundler integration tests passed!");
    log("Tests passed!");
  } catch (error) {
    console.error("❌ Bundler integration tests failed:", error);
    setStatus(
      "failure",
      "❌ Bundler integration tests failed. Check logs and browser console.",
    );
    log("Error: " + error.message);
    log(error.stack);
  }
}

runTests();
