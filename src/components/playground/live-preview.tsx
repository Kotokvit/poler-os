"use client";

import { useEffect, useRef, useCallback } from "react";
import { usePlaygroundStore } from "@/lib/playground-store";

export function LivePreview() {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const html = usePlaygroundStore((s) => s.html);
  const css = usePlaygroundStore((s) => s.css);
  const javascript = usePlaygroundStore((s) => s.javascript);

  const buildSrcDoc = useCallback(() => {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<style>${css}</style>
</head>
<body>
${html}
<script>${javascript}<\/script>
</body>
</html>`;
  }, [html, css, javascript]);

  useEffect(() => {
    if (!iframeRef.current) return;
    const doc = iframeRef.current.contentDocument;
    if (!doc) return;
    try {
      doc.open();
      doc.write(buildSrcDoc());
      doc.close();
    } catch {
      // fallback: set srcdoc
      iframeRef.current.srcdoc = buildSrcDoc();
    }
  }, [buildSrcDoc]);

  return (
    <div className="h-full w-full bg-white rounded-lg overflow-hidden">
      <iframe
        ref={iframeRef}
        title="Live Preview"
        className="w-full h-full border-0"
        sandbox="allow-scripts allow-modals"
        srcDoc={buildSrcDoc()}
      />
    </div>
  );
}
