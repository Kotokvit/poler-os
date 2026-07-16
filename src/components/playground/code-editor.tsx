"use client";

import dynamic from "next/dynamic";
import { usePlaygroundStore, CODE_TABS, type Language } from "@/lib/playground-store";

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-full text-zinc-500 text-sm">
      Loading editor...
    </div>
  ),
});

const MONACO_LANG_MAP: Record<Language, string> = {
  html: "html",
  css: "css",
  javascript: "javascript",
};

export function CodeEditor() {
  const activeTab = usePlaygroundStore((s) => s.activeTab);
  const html = usePlaygroundStore((s) => s.html);
  const css = usePlaygroundStore((s) => s.css);
  const javascript = usePlaygroundStore((s) => s.javascript);
  const setCode = usePlaygroundStore((s) => s.setCode);
  const setActiveTab = usePlaygroundStore((s) => s.setActiveTab);

  const currentCode = activeTab === "html" ? html : activeTab === "css" ? css : javascript;

  return (
    <div className="flex flex-col h-full">
      {/* Tab bar */}
      <div className="flex items-center gap-0 bg-[#1e1e2e] border-b border-zinc-800">
        {CODE_TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`
              px-4 py-2.5 text-xs font-medium tracking-wide transition-all
              flex items-center gap-1.5 border-b-2
              ${
                activeTab === tab.id
                  ? "text-white border-emerald-500 bg-[#181825]"
                  : "text-zinc-500 border-transparent hover:text-zinc-300 hover:bg-[#181825]/50"
              }
            `}
          >
            <span className="text-sm">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Editor */}
      <div className="flex-1 min-h-0">
        <MonacoEditor
          height="100%"
          language={MONACO_LANG_MAP[activeTab]}
          value={currentCode}
          onChange={(val) => setCode(activeTab, val ?? "")}
          theme="vs-dark"
          options={{
            fontSize: 14,
            fontFamily: "'Geist Mono', 'Fira Code', 'Cascadia Code', monospace",
            fontLigatures: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            padding: { top: 16 },
            lineNumbers: "on",
            renderLineHighlight: "line",
            automaticLayout: true,
            tabSize: 2,
            wordWrap: "on",
            bracketPairColorization: { enabled: true },
            smoothScrolling: true,
            cursorBlinking: "smooth",
            cursorSmoothCaretAnimation: "on",
          }}
        />
      </div>
    </div>
  );
}
