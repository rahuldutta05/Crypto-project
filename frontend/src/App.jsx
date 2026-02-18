import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Send from "./pages/Send";
import ChatPortal from "./pages/ChatPortal";
import Inbox from "./pages/Inbox";
import Register from "./pages/Register";
import Verify from "./pages/Verify";
import Attacker from "./pages/Attacker/Attacker";
import PacketSniffer from "./pages/Attacker/PacketSniffer";

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/"          element={<Send />} />
          <Route path="/chat"      element={<ChatPortal />} />
          <Route path="/inbox"     element={<Inbox />} />
          <Route path="/register"  element={<Register />} />
          <Route path="/verify"    element={<Verify />} />
          <Route path="/attacker"  element={<Attacker />} />
          <Route path="/sniffer"   element={<PacketSniffer />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
