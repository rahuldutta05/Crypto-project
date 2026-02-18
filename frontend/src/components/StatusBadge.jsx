export default function StatusBadge({ expired }) {
  return (
    <span className={`status-badge ${expired ? "expired" : "active"}`}>
      {expired ? "Expired" : "Active"}
    </span>
  );
}
