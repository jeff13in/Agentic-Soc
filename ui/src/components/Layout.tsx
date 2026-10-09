import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";

type Theme = "system" | "light" | "dark";

function readTheme(): Theme {
  try {
    const t = localStorage.getItem("theme");
    return t === "light" || t === "dark" ? t : "system";
  } catch {
    return "system";
  }
}

export function Layout() {
  const [theme, setTheme] = useState<Theme>(readTheme);
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);

  const link = ({ isActive }: { isActive: boolean }) =>
    `rounded px-2.5 py-1 text-sm ${isActive ? "bg-surface-2 font-medium text-ink" : "text-ink-2 hover:text-ink"}`;

  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2.5">
          <span className="font-semibold">SOC Triage Agent</span>
          <nav className="flex gap-1" aria-label="Main">
            <NavLink to="/" end className={link}>Alerts</NavLink>
            <NavLink to="/traces" className={link}>Traces</NavLink>
            <NavLink to="/evals" className={link}>Evals</NavLink>
          </nav>
          <label className="ml-auto flex items-center gap-1.5 text-xs text-muted">
            Theme
            <select value={theme} onChange={(e) => setTheme(e.target.value as Theme)}
              className="rounded border border-line bg-surface px-1.5 py-0.5 text-xs text-ink">
              <option value="system">System</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </label>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-5">
        <Outlet />
      </main>
    </div>
  );
}
