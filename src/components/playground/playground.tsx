"use client";

import { useCallback, useEffect, useState } from "react";
import { usePlaygroundStore } from "@/lib/playground-store";
import { Toolbar } from "./toolbar";
import { PlaygroundPanels } from "./playground-panels";
import { TooltipProvider } from "@/components/ui/tooltip";

export function Playground() {
  const [isDark, setIsDark] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const loadFromShare = usePlaygroundStore((s) => s.loadFromShare);

  // Load shared code from URL
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const shareData = params.get("share");
    if (shareData) {
      try {
        const decoded = JSON.parse(decodeURIComponent(escape(atob(shareData))));
        if (decoded.html && decoded.css && decoded.javascript) {
          loadFromShare(decoded);
        }
      } catch {
        // invalid share data, ignore
      }
    }
  }, [loadFromShare]);

  const handleToggleTheme = useCallback(() => {
    setIsDark((prev) => !prev);
    document.documentElement.classList.toggle("dark");
  }, []);

  const handleToggleFullscreen = useCallback(() => {
    setIsFullscreen((prev) => !prev);
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  }, []);

  return (
    <TooltipProvider delayDuration={300}>
      <div className="h-screen w-screen flex flex-col overflow-hidden bg-[#0a0a0f]">
        <Toolbar
          onToggleTheme={handleToggleTheme}
          isDark={isDark}
          onToggleFullscreen={handleToggleFullscreen}
        />
        <PlaygroundPanels />
        {/* Status bar */}
        <footer className="flex items-center justify-between px-3 py-1 bg-[#11111b] border-t border-zinc-800/50 text-[10px] text-zinc-600 font-mono">
          <span>Poler OS Playground</span>
          <span>v0.7.0 — x86_64 — Zig 0.13.0</span>
        </footer>
      </div>
    </TooltipProvider>
  );
}
