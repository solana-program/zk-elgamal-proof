import * as wasm from 'hello-wasm-universal';

async function run() {
    try {
        await wasm.default();
        const message = wasm.hello();
        document.getElementById('output').textContent = message;
    } catch (error) {
        console.error("Error initializing WASM module:", error);
        document.getElementById('output').textContent = 'Error loading WASM!';
        document.getElementById('output').style.color = 'red';
    }
}

run();
