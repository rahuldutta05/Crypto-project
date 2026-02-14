import API from "../services/api";
import { useEffect, useState } from "react";
import "../styles/attacker.css";

export default function Attacker() {

  const [data, setData] = useState({});

  useEffect(() => {
    async function intercept() {
      const res = await API.get("/admin/dump/messages");
      setData(res.data);
    }
    intercept();
  }, []);

    return (
    <div className="attacker-panel">
        <h2>Intercepted Ciphertext</h2>
        {Object.entries(data).map(([id, m]) => (
        <div className="ciphertext" key={id}>
            {m.encrypted_message}
        </div>
        ))}
    </div>
    );

}
