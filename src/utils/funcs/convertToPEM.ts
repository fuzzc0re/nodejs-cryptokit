export function convertToPEM(publicKeyBase64: string) {
  let resultString = "-----BEGIN PUBLIC KEY-----\n";
  let charCount = 0;
  let currentLine = "";
  for (const i of publicKeyBase64) {
    charCount += 1;
    currentLine += i;
    if (charCount === 64) {
      resultString += currentLine + "\n";
      charCount = 0;
      currentLine = "";
    }
  }
  if (currentLine.length > 0) {
    resultString += currentLine + "\n";
  }
  resultString += "-----END PUBLIC KEY-----";

  return resultString;
}
