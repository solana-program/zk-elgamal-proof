import {
  PubkeyValidityProofData,
  ElGamalKeypair,
} from "@solana/zk-sdk/bundler";

function log(message) {
  console.log(message);
  const logsElement = document.getElementById("logs");
  if (logsElement) {
    logsElement.textContent += message + "\n";
  }
}

function setStatus(statusClass, message) {
  const statusElement = document.getElementById("status");
  if (statusElement) {
    statusElement.className = statusClass;
    statusElement.textContent = message;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

async function runTests() {
  try {
    log("Wasm module initialized (handled by Webpack).");
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

    setStatus("success", "✅ Webpack integration tests passed!");
    log("Tests passed!");
  } catch (error) {
    console.error("❌ Webpack integration tests failed:", error);
    setStatus(
      "failure",
      "❌ Webpack integration tests failed. Check logs and browser console.",
    );
    log("Error: " + error.message);
    log(error.stack);
  }
}

runTests();
