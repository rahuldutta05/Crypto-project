import API from "../services/api";
import { useEffect, useState } from "react";
import "../styles/chat.css";

export default function Inbox() {

  const [msgs, setMsgs] = useState({});

  useEffect(() => {
    async function fetchMsgs() {
      const res = await API.get("/chat/inbox/deviceB");
      setMsgs(res.data);
    }
    fetchMsgs();
  }, []);

  return (
  <div className="chat-box">
    {Object.entries(msgs).map(([id, m]) => (
      <div className="message" key={id}>
        {m.encrypted_message}
      </div>
    ))}
  </div>
);

}
