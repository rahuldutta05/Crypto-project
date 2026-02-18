export default function MessageBubble({ msg, sender }) {
  return (
    <div className={`message-bubble ${sender ? "sent" : "received"}`}>
      <div className="bubble-content">{msg}</div>
    </div>
  );
}
