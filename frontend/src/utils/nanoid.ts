const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
const alphabetLength = alphabet.length;

export const nanoid = (size = 12): string => {
  let id = '';
  const cryptoObj = globalThis.crypto || (globalThis as unknown as { msCrypto?: Crypto }).msCrypto;
  const randomBuffer = new Uint32Array(size);
  if (cryptoObj && cryptoObj.getRandomValues) {
    cryptoObj.getRandomValues(randomBuffer);
    for (let i = 0; i < size; i += 1) {
      id += alphabet[randomBuffer[i] % alphabetLength];
    }
    return id;
  }

  for (let i = 0; i < size; i += 1) {
    const randomIndex = Math.floor(Math.random() * alphabetLength);
    id += alphabet[randomIndex];
  }
  return id;
};
