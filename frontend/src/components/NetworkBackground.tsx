"use client";

import { useEffect, useRef } from "react";
import { useTheme } from "./ThemeProvider";

const CHARS = "0123456789ABCDEFabcdef<>/\\{}[]|!@#$_+-=;:.?";
const CHAR_SIZE = 14;

interface Stream {
  x: number;
  y: number;       // current head y in pixels
  speed: number;   // pixels per frame
  length: number;  // trail length in chars
  chars: string[]; // current visible chars (length + 1)
  timer: number;   // frame counter for char shuffle
}

function randChar() {
  return CHARS[Math.floor(Math.random() * CHARS.length)];
}

export default function NetworkBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef    = useRef<number>(0);
  const { theme } = useTheme();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reducedMotion =
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (reducedMotion) return;

    let W = window.innerWidth;
    let H = window.innerHeight;
    let streams: Stream[] = [];

    const isLight = theme === "light";
    // Light mode: very subtle dark-on-light; dark mode: neon green
    const headColor  = isLight ? "rgba(0,80,208,0.55)"  : "rgba(0,255,157,0.90)";
    const midColor   = isLight ? "rgba(0,80,208,0.22)"  : "rgba(0,255,157,0.45)";
    const tailColor  = isLight ? "rgba(0,80,208,0.08)"  : "rgba(0,255,157,0.15)";
    const bgFade     = isLight ? "rgba(240,242,245,0.15)" : "rgba(13,17,23,0.12)";

    const init = () => {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;

      const cols = Math.floor(W / CHAR_SIZE);
      streams = [];
      for (let i = 0; i < cols; i++) {
        // Only spawn ~60% of columns to keep it sparse
        if (Math.random() > 0.6) continue;
        const len = Math.floor(Math.random() * 18) + 8;
        streams.push({
          x:      i * CHAR_SIZE,
          y:      Math.random() * H * 1.5 - H * 0.5,
          speed:  Math.random() * 1.5 + 0.8,
          length: len,
          chars:  Array.from({ length: len + 1 }, randChar),
          timer:  Math.floor(Math.random() * 20),
        });
      }
    };

    init();
    window.addEventListener("resize", init);

    ctx.font = `${CHAR_SIZE}px 'JetBrains Mono', monospace`;

    let frame = 0;

    const draw = () => {
      // Fade previous frame (creates trail)
      ctx.fillStyle = bgFade;
      ctx.fillRect(0, 0, W, H);

      ctx.font = `${CHAR_SIZE}px 'JetBrains Mono', monospace`;

      for (const s of streams) {
        s.y += s.speed;
        s.timer++;

        // Shuffle chars periodically for "changing code" effect
        if (s.timer % 6 === 0) {
          s.chars[0] = randChar();
          if (Math.random() < 0.3) {
            const idx = Math.floor(Math.random() * s.chars.length);
            s.chars[idx] = randChar();
          }
        }

        // Reset stream when it scrolls off screen
        if (s.y - s.length * CHAR_SIZE > H) {
          s.y = -CHAR_SIZE * (Math.floor(Math.random() * 10) + 2);
          s.speed  = Math.random() * 1.5 + 0.8;
          s.length = Math.floor(Math.random() * 18) + 8;
          s.chars  = Array.from({ length: s.length + 1 }, randChar);
        }

        // Draw trail chars from head going up
        for (let j = 0; j <= s.length; j++) {
          const cy = s.y - j * CHAR_SIZE;
          if (cy < -CHAR_SIZE || cy > H) continue;

          if (j === 0) {
            // Head — brightest
            ctx.fillStyle = headColor;
          } else if (j < 3) {
            ctx.fillStyle = midColor;
          } else {
            // Tail fades out
            const alpha = (1 - j / s.length);
            if (alpha <= 0) continue;
            ctx.fillStyle = isLight
              ? `rgba(0,80,208,${(alpha * 0.06).toFixed(3)})`
              : `rgba(0,255,157,${(alpha * 0.12).toFixed(3)})`;
          }

          const char = s.chars[j] ?? randChar();
          ctx.fillText(char, s.x, cy);
        }

        // Extra bright glow on the leading char (dark mode only)
        if (!isLight && s.y >= 0 && s.y <= H) {
          ctx.fillStyle = "rgba(180,255,230,0.85)";
          ctx.fillText(s.chars[0], s.x, s.y);
        }
      }

      frame++;
      rafRef.current = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener("resize", init);
    };
  }, [theme]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position:      "fixed",
        inset:         0,
        zIndex:        0,
        pointerEvents: "none",
        opacity:       0.55,
      }}
    />
  );
}
