import { useState } from "react";
import { pct } from "../lib/format";

export interface Bar {
  label: string;
  value: number | null;
  detail?: string;
}

/** Horizontal bars for rates in [0, 1]. One series, so the title names it and there is no legend. */
export function RateBarChart({ bars, title }: { bars: Bar[]; title: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);
  const labelW = 96;
  const valueW = 56;
  const rowH = 30;
  const barH = 14;
  const width = 520;
  const plotW = width - labelW - valueW;
  const height = bars.length * rowH + 22;
  const ticks = [0, 0.25, 0.5, 0.75, 1];

  return (
    <figure>
      <figcaption className="mb-2 flex items-center justify-between text-sm font-medium">
        {title}
        <button type="button" className="text-xs font-normal text-accent-ink hover:underline"
          onClick={() => setShowTable(!showTable)}>{showTable ? "Show chart" : "Show table"}</button>
      </figcaption>
      {showTable ? (
        <table className="text-sm tabular">
          <tbody>
            {bars.map((b) => (
              <tr key={b.label}><td className="pr-6 text-ink-2">{b.label}</td><td>{pct(b.value)}</td>
                <td className="pl-4 text-xs text-muted">{b.detail}</td></tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="relative">
          <svg viewBox={`0 0 ${width} ${height}`} className="w-full max-w-[560px]" role="img" aria-label={title}>
            {ticks.map((t) => {
              const x = labelW + t * plotW;
              return (
                <g key={t}>
                  <line x1={x} x2={x} y1={0} y2={height - 18} stroke="var(--grid)" strokeWidth={1} />
                  <text x={x} y={height - 4} textAnchor="middle" fontSize={10} fill="var(--muted)" className="tabular">
                    {t * 100}%
                  </text>
                </g>
              );
            })}
            <line x1={labelW} x2={labelW} y1={0} y2={height - 18} stroke="var(--axis)" strokeWidth={1} />
            {bars.map((b, i) => {
              const y = i * rowH + (rowH - barH) / 2;
              const w = Math.max(0, (b.value ?? 0) * plotW);
              return (
                <g key={b.label} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
                  {/* hit target is the whole row, larger than the mark */}
                  <rect x={0} y={i * rowH} width={width} height={rowH} fill="transparent" />
                  <text x={labelW - 8} y={y + barH / 2 + 4} textAnchor="end" fontSize={12} fill="var(--ink-2)">{b.label}</text>
                  {b.value !== null && w > 0 && (
                    <path d={roundedBar(labelW, y, w, barH)} fill="var(--series-1)"
                      opacity={hover === null || hover === i ? 1 : 0.55} />
                  )}
                  <text x={labelW + w + 6} y={y + barH / 2 + 4} fontSize={12} fill="var(--ink)" className="tabular">
                    {b.value === null ? "n/a" : pct(b.value)}
                  </text>
                </g>
              );
            })}
          </svg>
          {hover !== null && bars[hover].detail && (
            <div className="pointer-events-none absolute left-24 rounded border border-line bg-surface px-2 py-1 text-xs shadow"
              style={{ top: hover * rowH + rowH }}>
              <strong>{bars[hover].label}</strong>: {bars[hover].detail}
            </div>
          )}
        </div>
      )}
    </figure>
  );
}

/** Bar anchored at the baseline (square left end) with a 4px rounded data end. */
function roundedBar(x: number, y: number, w: number, h: number): string {
  const r = Math.min(4, w, h / 2);
  return `M${x},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + h - r} Q${x + w},${y + h} ${x + w - r},${y + h} H${x} Z`;
}
