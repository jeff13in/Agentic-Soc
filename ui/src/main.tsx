import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import "./index.css";
import { AlertDetail } from "./pages/AlertDetail";
import { AlertQueue } from "./pages/AlertQueue";
import { EvalDashboard } from "./pages/EvalDashboard";
import { TraceList } from "./pages/TraceList";
import { TraceViewer } from "./pages/TraceViewer";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<AlertQueue />} />
          <Route path="alerts/:id" element={<AlertDetail />} />
          <Route path="traces" element={<TraceList />} />
          <Route path="traces/:id" element={<TraceViewer />} />
          <Route path="evals" element={<EvalDashboard />} />
          <Route path="*" element={<p className="text-sm text-ink-2">Page not found.</p>} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
