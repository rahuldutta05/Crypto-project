import { useState } from "react";
import API from "../services/api";
import "../styles/main.css";
import "../styles/chat.css";
import "../styles/attacker.css";

export default function ChatPortal() {

  const [device, setDevice] = useState("deviceA");
  const [msg, setMsg] = useState("");
  const [inbox, setInbox] = useState({});
  const [attacker, setAttacker] = useState({});

  async function registerDev() {
    await API.post("/keys/register", {
      user_id: device,
      public_key: "dummy"
    });
    alert(device + " registered");
  }

  async function sendMsg() {

    await API.post("/chat/send", {
      encrypted_message: msg,
      encrypted_key: "dummyAES",
      receiver: device === "deviceA" ? "deviceB" : "deviceA"
    });

    alert("Encrypted message sent!");
  }

  async function fetchInbox() {
    const res = await API.get("/chat/inbox/" + device);
    setInbox(res.data);
  }

  async function intercept() {
    const res = await API.get("/admin/dump/messages");
    setAttacker(res.data);
  }

  return (
    <div className="container">

      <h1>Secure Anonymous Communication Portal</h1>

      <select
        value={device}
        onChange={e => setDevice(e.target.value)}
      >
        <option value="deviceA">Device A</option>
        <option value="deviceB">Device B</option>
      </select>

      <button onClick={registerDev}>
        Register Device
      </button>

      <div className="chat-panel">

        <input
          value={msg}
          onChange={e => setMsg(e.target.value)}
          placeholder="Enter message"
        />

        <button onClick={sendMsg}>
          Send Encrypted Message
        </button>

        <button onClick={fetchInbox}>
          Fetch Inbox
        </button>

      </div>

      <div className="chat-box">
        <h3>Inbox</h3>
        {Object.entries(inbox).map(([id, m]) => (
          <div className="message" key={id}>
            {m.encrypted_message}
          </div>
        ))}
      </div>

      <button onClick={intercept}>
        Simulate Attacker
      </button>

      <div className="attacker-panel">
        <h3>Intercepted Ciphertext</h3>
        {Object.entries(attacker).map(([id, m]) => (
          <div className="ciphertext" key={id}>
            {m.encrypted_message}
          </div>
        ))}
      </div>

    </div>
  );
}
