"use client";

import { useEffect, useRef, useState } from "react";

const STAGES = [
  { label: "email_parsing",       desc: "MIME decomposition · header extraction",              ms: 900  },
  { label: "header_analysis",     desc: "SPF · DKIM · DMARC · relay hop tracing",              ms: 1100 },
  { label: "url_scanning",        desc: "URL fingerprinting · obfuscation detection",          ms: 1400 },
  { label: "domain_intelligence", desc: "WHOIS · DNS enumeration · typosquat scoring",         ms: 2400 },
  { label: "threat_intel",        desc: "OpenPhish · PhishTank · URLhaus correlation",         ms: 2200 },
  { label: "nlp_analysis",        desc: "Social engineering language pattern detection",       ms: 800  },
  { label: "feature_engineering", desc: "80-feature adversarial vector assembly",              ms: 600  },
  { label: "risk_scoring",        desc: "Dual-bucket suspicion / trust engine",                ms: 0    },
  { label: "report_generation",   desc: "IOC report · STIX2 · SIEM export",                   ms: 600  },
];

const HOLD_AT = 7;
type StageStatus = "done" | "running" | "pending" | "failed";

interface Props {
  status: "pending" | "processing" | "complete" | "failed";
  analysisId: string;
  artifactType?: string;
}

/* ── tiny blinking dots for active stage ── */
function Dots() {
  const [n, setN] = useState(1);
  useEffect(() => {
    const id = setInterval(() => setN(x => (x % 3) + 1), 500);
    return () => clearInterval(id);
  }, []);
  return <span style={{ color: "var(--color-phismail-purple)", letterSpacing: 2 }}>{"•".repeat(n)}</span>;
}

export default function AnalysisTimeline({ status, analysisId, artifactType }: Props) {
  const [active, setActive]   = useState(0);
  const [times, setTimes]     = useState<Record<number, number>>({});
  const [allDone, setAllDone] = useState(false);
  const [elapsed, setElapsed] = useState(0);

  const timerRef   = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stageStart = useRef(Date.now());

  /* elapsed counter */
  useEffect(() => {
    const id = setInterval(() => setElapsed(s => s + 1), 1000);
    return () => clearInterval(id);
  }, []);

  /* stage ticker */
  useEffect(() => {
    if (status === "failed" || allDone) return;
    const advance = () => {
      setActive(prev => {
        const t = Date.now() - stageStart.current;
        setTimes(m => ({ ...m, [prev]: t }));
        stageStart.current = Date.now();
        if (prev === HOLD_AT && status !== "complete") return prev;
        const next = prev + 1;
        if (next >= STAGES.length) { setAllDone(true); return prev; }
        if (STAGES[next].ms > 0) timerRef.current = setTimeout(advance, STAGES[next].ms);
        return next;
      });
    };
    if (STAGES[active].ms > 0 && active < HOLD_AT)
      timerRef.current = setTimeout(advance, STAGES[active].ms);
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* flush when backend complete */
  useEffect(() => {
    if (status === "complete" && active >= HOLD_AT && !allDone) {
      setTimes(m => ({ ...m, [HOLD_AT]: Date.now() - stageStart.current }));
      stageStart.current = Date.now();
      setActive(HOLD_AT + 1);
      timerRef.current = setTimeout(() => {
        setTimes(m => ({ ...m, [HOLD_AT + 1]: Date.now() - stageStart.current }));
        setAllDone(true);
      }, STAGES[HOLD_AT + 1].ms);
    }
    if (status === "complete" && active < HOLD_AT) setTimeout(() => setAllDone(true), 400);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  const getStatus = (i: number): StageStatus => {
    if (status === "failed") return i < active ? "done" : i === active ? "failed" : "pending";
    if (allDone) return "done";
    return i < active ? "done" : i === active ? "running" : "pending";
  };

  const isFailed  = status === "failed";
  const doneCount = allDone ? STAGES.length : active;
  const pct       = Math.round((doneCount / STAGES.length) * 100);
  const mm        = String(Math.floor(elapsed / 60)).padStart(2, "0");
  const ss        = String(elapsed % 60).padStart(2, "0");
  const curStage  = STAGES[Math.min(active, STAGES.length - 1)];

  /* SVG ring */
  const R  = 54;
  const C  = 2 * Math.PI * R;
  const offset = C - (pct / 100) * C;

  return (
    <div className="font-mono" style={{ color: "var(--color-phismail-text)" }}>

      {/* ════════════════════════════════════════
          TOP META BAR
      ════════════════════════════════════════ */}
      <div
        className="flex items-center justify-between flex-wrap gap-3 px-6 py-3 mb-10 rounded"
        style={{
          background:  "var(--color-phismail-surface)",
          border:      `1px solid ${isFailed ? "rgba(248,81,73,0.3)" : "var(--color-phismail-border)"}`,
        }}
      >
        {/* Left: status + type */}
        <div className="flex items-center gap-3">
          <span
            className="text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded"
            style={{
              background: isFailed ? "rgba(248,81,73,0.12)" : allDone ? "rgba(63,185,80,0.10)" : "var(--color-phismail-purple-glow)",
              color:      isFailed ? "#f85149"              : allDone ? "#3fb950"               : "var(--color-phismail-purple)",
              border:     `1px solid ${isFailed ? "rgba(248,81,73,0.3)" : allDone ? "rgba(63,185,80,0.3)" : "rgba(0,112,243,0.3)"}`,
            }}
          >
            {isFailed ? "FAILED" : allDone ? "COMPLETE" : "ANALYZING"}
          </span>
          {artifactType && (
            <span className="text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
              {artifactType.toUpperCase()} artifact
            </span>
          )}
        </div>

        {/* Right: ID + elapsed */}
        <div className="flex items-center gap-4 text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
          <span className="truncate max-w-[12rem]">{analysisId}</span>
          <span className="tabular-nums shrink-0" style={{ color: "var(--color-phismail-text-dim)" }}>
            {mm}:{ss}
          </span>
        </div>
      </div>

      {/* ════════════════════════════════════════
          CENTER — RING + CURRENT STAGE
      ════════════════════════════════════════ */}
      <div className="flex flex-col items-center gap-6 mb-12">

        {/* SVG ring */}
        <div className="relative" style={{ width: 140, height: 140 }}>
          <svg width="140" height="140" viewBox="0 0 140 140" style={{ transform: "rotate(-90deg)" }}>
            {/* Track */}
            <circle
              cx="70" cy="70" r={R}
              fill="none"
              stroke="var(--color-phismail-surface)"
              strokeWidth="6"
            />
            {/* Progress arc */}
            <circle
              cx="70" cy="70" r={R}
              fill="none"
              stroke={isFailed ? "#f85149" : allDone ? "#3fb950" : "var(--color-phismail-purple)"}
              strokeWidth="6"
              strokeLinecap="round"
              strokeDasharray={C}
              strokeDashoffset={offset}
              style={{
                transition: "stroke-dashoffset 0.8s ease",
                filter: `drop-shadow(0 0 6px ${isFailed ? "rgba(248,81,73,0.5)" : allDone ? "rgba(63,185,80,0.5)" : "rgba(0,112,243,0.5)"})`,
              }}
            />
          </svg>
          {/* Center text */}
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5">
            <span
              className="text-3xl font-bold tabular-nums"
              style={{ color: isFailed ? "#f85149" : allDone ? "#3fb950" : "var(--color-phismail-purple)" }}
            >
              {pct}
            </span>
            <span className="text-[10px] uppercase tracking-widest" style={{ color: "var(--color-phismail-text-dim)" }}>
              %
            </span>
          </div>
        </div>

        {/* Current stage label */}
        <div className="text-center space-y-1">
          {allDone ? (
            <p className="text-sm font-bold" style={{ color: "#3fb950" }}>
              report ready — loading
              <span className="terminal-cursor" />
            </p>
          ) : isFailed ? (
            <p className="text-sm font-bold" style={{ color: "#f85149" }}>pipeline halted</p>
          ) : (
            <>
              <p className="text-sm font-semibold" style={{ color: "var(--color-phismail-text)" }}>
                {curStage.label}
              </p>
              <p className="text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
                {curStage.desc}
              </p>
              <p className="text-xs mt-1">
                <Dots />
              </p>
            </>
          )}
        </div>

        {/* Stage counter */}
        <div className="flex items-center gap-2 text-xs" style={{ color: "var(--color-phismail-text-muted)" }}>
          <span style={{ color: "var(--color-phismail-purple)" }}>{doneCount}</span>
          <span style={{ color: "var(--color-phismail-text-dim)" }}>/</span>
          <span>{STAGES.length}</span>
          <span style={{ color: "var(--color-phismail-text-dim)" }}>stages complete</span>
        </div>
      </div>

      {/* ════════════════════════════════════════
          STAGE LIST
      ════════════════════════════════════════ */}
      <div
        className="rounded overflow-hidden"
        style={{ border: "1px solid var(--color-phismail-border)" }}
      >
        {STAGES.map((stage, i) => {
          const s   = getStatus(i);
          const t   = times[i];
          const isDone    = s === "done";
          const isRunning = s === "running";
          const isPending = s === "pending";
          const isFail    = s === "failed";

          return (
            <div
              key={stage.label}
              className="flex items-center gap-4 px-5 py-3 text-xs"
              style={{
                background:   isRunning ? "var(--color-phismail-purple-glow)" : "transparent",
                borderBottom: i < STAGES.length - 1 ? "1px solid var(--color-phismail-border)" : "none",
                opacity:      isPending ? 0.28 : 1,
                transition:   "opacity 0.4s ease, background 0.3s ease",
              }}
            >
              {/* Index */}
              <span className="text-[10px] w-5 shrink-0 tabular-nums text-right"
                style={{ color: "var(--color-phismail-text-dim)" }}
              >
                {String(i + 1).padStart(2, "0")}
              </span>

              {/* Glyph */}
              <span
                className="w-4 shrink-0 text-center font-bold text-sm"
                style={{
                  color: isDone    ? "#3fb950"
                       : isRunning ? "var(--color-phismail-purple)"
                       : isFail    ? "#f85149"
                       : "var(--color-phismail-text-dim)",
                }}
              >
                {isDone ? "✓" : isRunning ? "›" : isFail ? "✗" : "·"}
              </span>

              {/* Stage name */}
              <span
                className="flex-1 min-w-0 truncate"
                style={{
                  color: isDone    ? "var(--color-phismail-text)"
                       : isRunning ? "var(--color-phismail-purple)"
                       : isFail    ? "#f85149"
                       : "var(--color-phismail-text-muted)",
                  fontWeight: isRunning ? 600 : 400,
                }}
              >
                {stage.label}
              </span>

              {/* Description — only visible when done or running */}
              {(isDone || isRunning) && (
                <span
                  className="hidden md:block text-[11px] truncate"
                  style={{ color: "var(--color-phismail-text-dim)", maxWidth: "18rem" }}
                >
                  {stage.desc}
                </span>
              )}

              {/* Time / running indicator */}
              <span className="shrink-0 tabular-nums ml-auto pl-4"
                style={{ color: "var(--color-phismail-text-dim)", minWidth: "3rem", textAlign: "right" }}
              >
                {isDone && t !== undefined ? `${(t / 1000).toFixed(1)}s`
                 : isRunning ? <Dots />
                 : ""}
              </span>
            </div>
          );
        })}
      </div>

      {/* ════════════════════════════════════════
          BOTTOM PROGRESS BAR
      ════════════════════════════════════════ */}
      <div className="mt-4">
        <div className="h-0.5 rounded-full overflow-hidden" style={{ background: "var(--color-phismail-surface)" }}>
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{
              width:      `${pct}%`,
              background: isFailed ? "#f85149" : allDone ? "#3fb950" : "var(--color-phismail-purple)",
              boxShadow:  `0 0 8px ${isFailed ? "rgba(248,81,73,0.5)" : allDone ? "rgba(63,185,80,0.5)" : "rgba(0,112,243,0.5)"}`,
            }}
          />
        </div>
      </div>

    </div>
  );
}
