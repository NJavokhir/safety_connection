(async function () {
    const go = new Go();
    await WebAssembly.instantiateStreaming(
      fetch("main.wasm"),
      go.importObject
    ).then((result) => {
      go.run(result.instance);
    })
  })();