import API from "../services/api";
import { generateKeyPair, exportPublicKey } from "../crypto/rsaClient";
import { exportPrivateKey } from "../crypto/rsaClient";

export default function Register() {

  async function handleRegister() {

    const keys = await generateKeyPair();
    const pub = await exportPublicKey(keys.publicKey);

    const priv = await exportPrivateKey(keys.privateKey);
    localStorage.setItem("privateKey", priv);

    await API.post("/keys/register", {
      user_id: "deviceA",
      public_key: pub
    });

    alert("Registered!");
  }

  return (
    <button onClick={handleRegister}>
      Register Device
    </button>
  );
}
