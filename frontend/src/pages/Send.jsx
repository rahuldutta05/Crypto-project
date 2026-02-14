import API from "../services/api";
import { generateAESKey, encryptMessage } from "../crypto/aesClient";

export default function Send() {

  async function sendMsg() {

  const aes = await generateAESKey();
  const encryptedMsg = await encryptMessage("Hello B!", aes);

  const receiverKeyRes = await API.get("/keys/deviceB");
  const pubKeyBase64 = receiverKeyRes.data.public_key;

  const binary = Uint8Array.from(atob(pubKeyBase64), c => c.charCodeAt(0));

  const publicKey = await crypto.subtle.importKey(
    "spki",
    binary,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );

  const encryptedAES = await encryptAESKey(aes, publicKey);

  await API.post("/chat/send", {
    encrypted_message: encryptedMsg.ciphertext,
    encrypted_key: btoa(String.fromCharCode(...new Uint8Array(encryptedAES))),
    receiver: "deviceB"
  });

  alert("Secure Message Sent!");
}

}
export async function exportPrivateKey(key) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
  return btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
}
