"use client";

import { useState, useCallback } from "react";
import { usePlaygroundStore, DEFAULT_HTML, DEFAULT_CSS, DEFAULT_JS } from "@/lib/playground-store";
import { Button } from "@/components/ui/button";
import {
  Share2,
  Copy,
  Check,
  RotateCcw,
  Moon,
  Sun,
  Maximize2,
  Code2,
} from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface ToolbarProps {
  onToggleTheme: () => void;
  isDark: boolean;
  onToggleFullscreen: () => void;
}

export function Toolbar({ onToggleTheme, isDark, onToggleFullscreen }: ToolbarProps) {
  const [copied, setCopied] = useState(false);
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const isSharing = usePlaygroundStore((s) => s.isSharing);
  const setIsSharing = usePlaygroundStore((s) => s.setIsSharing);
  const setShareId = usePlaygroundStore((s) => s.setShareId);
  const html = usePlaygroundStore((s) => s.html);
  const css = usePlaygroundStore((s) => s.css);
  const javascript = usePlaygroundStore((s) => s.javascript);
  const loadFromShare = usePlaygroundStore((s) => s.loadFromShare);

  const handleReset = useCallback(() => {
    loadFromShare({
      html: DEFAULT_HTML,
      css: DEFAULT_CSS,
      javascript: DEFAULT_JS,
    });
  }, [loadFromShare]);

  const handleShare = useCallback(async () => {
    setIsSharing(true);
    try {
      const payload = { html, css, javascript };
      const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
      const id = encoded.slice(0, 12);
      setShareId(id);
      const url = `${window.location.origin}?share=${encodeURIComponent(encoded)}`;
      setShareUrl(url);
    } catch {
      // fallback: copy raw
    } finally {
      setIsSharing(false);
    }
  }, [html, css, javascript, setIsSharing, setShareId]);

  const handleCopy = useCallback(async () => {
    if (!shareUrl) return;
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  }, [shareUrl]);

  return (
    <header className="flex items-center justify-between px-4 py-2 bg-[#11111b] border-b border-zinc-800/50">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <Code2 className="w-5 h-5 text-emerald-500" />
          <h1 className="text-sm font-semibold tracking-tight">
            <span className="text-emerald-400">Poler</span>
            <span className="text-zinc-400"> Playground</span>
          </h1>
        </div>
        <span className="text-[10px] text-zinc-600 bg-zinc-800/50 px-2 py-0.5 rounded-full font-mono">
          v0.7.0
        </span>
      </div>

      <div className="flex items-center gap-1">
        <Tooltip>
          <TooltipTrigger
            className="inline-flex items-center justify-center h-8 w-8 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
            onClick={handleReset}
          >
            <RotateCcw className="w-4 h-4" />
          </TooltipTrigger>
          <TooltipContent>Reset to default</TooltipContent>
        </Tooltip>

        <Tooltip>
          <TooltipTrigger
            className="inline-flex items-center justify-center h-8 w-8 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
            onClick={onToggleTheme}
          >
            {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </TooltipTrigger>
          <TooltipContent>Toggle theme</TooltipContent>
        </Tooltip>

        <Tooltip>
          <TooltipTrigger
            className="inline-flex items-center justify-center h-8 w-8 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
            onClick={onToggleFullscreen}
          >
            <Maximize2 className="w-4 h-4" />
          </TooltipTrigger>
          <TooltipContent>Fullscreen preview</TooltipContent>
        </Tooltip>

        {shareUrl ? (
          <div className="flex items-center gap-1 ml-2 bg-zinc-800/50 rounded-lg px-2 py-1">
            <input
              readOnly
              value={shareUrl}
              className="bg-transparent text-xs text-zinc-300 w-48 outline-none font-mono truncate"
              onClick={(e) => (e.target as HTMLInputElement).select()}
            />
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 text-zinc-400 hover:text-emerald-400"
              onClick={handleCopy}
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </Button>
          </div>
        ) : (
          <Button
            variant="ghost"
            size="sm"
            className="ml-2 h-8 gap-1.5 text-zinc-400 hover:text-white hover:bg-zinc-800 text-xs"
            onClick={handleShare}
            disabled={isSharing}
          >
            <Share2 className="w-3.5 h-3.5" />
            Share
          </Button>
        )}
      </div>
    </header>
  );
}
