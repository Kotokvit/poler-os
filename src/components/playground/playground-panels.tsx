"use client";

import { CodeEditor } from "./code-editor";
import { LivePreview } from "./live-preview";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

export function PlaygroundPanels() {
  return (
    <ResizablePanelGroup
      direction="horizontal"
      className="flex-1 min-h-0"
    >
      {/* Code Editor Panel */}
      <ResizablePanel defaultSize={50} minSize={25} maxSize={75}>
        <div className="h-full bg-[#1e1e2e]">
          <CodeEditor />
        </div>
      </ResizablePanel>

      <ResizableHandle className="bg-zinc-800 hover:bg-emerald-500/50 active:bg-emerald-500 transition-colors w-[3px]" />

      {/* Preview Panel */}
      <ResizablePanel defaultSize={50} minSize={25} maxSize={75}>
        <div className="h-full flex flex-col bg-[#11111b]">
          {/* Preview header */}
          <div className="flex items-center px-3 py-2 bg-[#1e1e2e] border-b border-zinc-800">
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
              <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
              <div className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
            </div>
            <span className="ml-3 text-[11px] text-zinc-500 font-mono">
              Preview
            </span>
            <div className="ml-auto flex items-center gap-1">
              <span className="text-[10px] text-emerald-500/70 bg-emerald-500/10 px-1.5 py-0.5 rounded font-mono">
                LIVE
              </span>
            </div>
          </div>
          {/* Preview iframe */}
          <div className="flex-1 p-2">
            <LivePreview />
          </div>
        </div>
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}
