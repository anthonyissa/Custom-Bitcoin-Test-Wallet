const fs = require("fs");
const crypto = require("crypto");
const elliptic = require("elliptic");

// Initialize the elliptic curve library for secp256k1
const ec = new elliptic.ec("secp256k1");

function generateMasterPrivateKeyFromSeedPhrase(seedPhrase) {
  const seed = crypto.createHash("sha256").update(seedPhrase).digest();

  const privateKey = ec.keyFromPrivate(seed);

  const privateKeyHex = privateKey.getPrivate("hex");

  return privateKeyHex;
}

function generateMasterPublicKeyFromPrivateKey(privateKey) {
  const publicKey = ec.keyFromPrivate(privateKey).getPublic();

  const publicKeyHex = publicKey.encode("hex");

  return publicKeyHex;
}

function generateChildKeyFromParentKey(parentKey, index) {
  const parentKeyPair = ec.keyFromPrivate(parentKey);

  const childKeyPair = parentKeyPair.derive(index);

  const childPrivateKey = childKeyPair.getPrivate("hex");

  const childPublicKey = childKeyPair.getPublic("hex");

  return { childPrivateKey, childPublicKey };
}

function generateSecureSeed() {
  const numBits = 128;
  const numBytes = numBits / 8;
  const seed = new Uint8Array(numBytes);

  for (let i = 0; i < numBytes; i++) {
    seed[i] = Math.floor(Math.random() * 256);
  }

  return seed;
}

function seedToBinaryAndChunks(seed) {
  let binaryString = "";
  for (let i = 0; i < seed.length; i++) {
    binaryString += seed[i].toString(2).padStart(8, "0");
  }

  const chunkSize = 11;
  const chunks = [];
  for (let i = 0; i < binaryString.length; i += chunkSize) {
    chunks.push(binaryString.slice(i, i + chunkSize));
  }

  return chunks;
}

function attributeWordsToSeed(secureSeed) {
  const wordList = fs.readFileSync("wordlist.txt", "utf8").split("\n");
  const words = [];
  for (const value of secureSeed) {
    words.push(wordList[value]);
  }
  return words;
}

function createWallet() {
  const importedMnemonic = process.argv[2];
  if (importedMnemonic) {
    console.log("Imported mnemonic:", importedMnemonic);
    return importedMnemonic;
  } else {
    const secureSeed = generateSecureSeed();
    console.log("Seed générée de manière sécurisée:", secureSeed);
    const keys = generateKeys(secureSeed);
    const binaryChunks = seedToBinaryAndChunks(secureSeed);
    console.log("Seed en binaire et découpée en lots de 11 bits:");
    binaryChunks.forEach((chunk, index) => {
      console.log(`Lot ${index + 1}: ${chunk}`);
    });
    const seed = attributeWordsToSeed(secureSeed);
    console.log("Seed:", seed);
    return { seed, ...keys };
  }
}

function generateKeys(binarySeed) {
  const masterPrivateKey = generateMasterPrivateKeyFromSeedPhrase(binarySeed);
  const masterPublicKey =
    generateMasterPublicKeyFromPrivateKey(masterPrivateKey);
  //   const childKey = generateChildKeyFromParentKey(masterPrivateKey, 1);
  return { masterPrivateKey, masterPublicKey };
}

function main() {
  const wallet = createWallet();
  console.log(wallet);
}

main();
