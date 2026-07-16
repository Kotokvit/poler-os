import { create } from "zustand";

export type Language = "html" | "css" | "javascript";

export interface CodeTab {
  id: Language;
  label: string;
  icon: string;
}

export const CODE_TABS: CodeTab[] = [
  { id: "html", label: "HTML", icon: "📦" },
  { id: "css", label: "CSS", icon: "🎨" },
  { id: "javascript", label: "JS", icon: "⚡" },
];

export const DEFAULT_HTML = `<div class="container">
  <h1>Hello, Poler OS! 🚀</h1>
  <p>Edit the code on the left to see live changes on the right.</p>
  <div class="card">
    <h2>Getting Started</h2>
    <p>Try changing the HTML, CSS, or JavaScript tabs.</p>
    <button id="action-btn">Click Me</button>
  </div>
</div>`;

export const DEFAULT_CSS = `* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
  color: #e0e0e0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
}

.container {
  text-align: center;
  padding: 2rem;
}

h1 {
  font-size: 2.5rem;
  margin-bottom: 0.5rem;
  background: linear-gradient(90deg, #ff6b6b, #feca57, #48dbfb, #ff9ff3);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: gradient 3s ease infinite;
}

@keyframes gradient {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

p {
  color: #aaa;
  margin-bottom: 1.5rem;
  font-size: 1.1rem;
}

.card {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 16px;
  padding: 2rem;
  max-width: 400px;
  margin: 0 auto;
  backdrop-filter: blur(10px);
}

.card h2 {
  font-size: 1.3rem;
  margin-bottom: 0.75rem;
  color: #48dbfb;
}

button {
  margin-top: 1rem;
  padding: 0.75rem 2rem;
  background: linear-gradient(135deg, #6c5ce7, #a29bfe);
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 1rem;
  cursor: pointer;
  transition: all 0.3s ease;
}

button:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(108, 92, 231, 0.4);
}`;

export const DEFAULT_JS = `document.getElementById('action-btn').addEventListener('click', function() {
  this.textContent = '🎉 Clicked!';
  this.style.background = 'linear-gradient(135deg, #00b894, #55efc4)';
  setTimeout(() => {
    this.textContent = 'Click Me';
    this.style.background = 'linear-gradient(135deg, #6c5ce7, #a29bfe)';
  }, 1500);
});`;

interface PlaygroundState {
  html: string;
  css: string;
  javascript: string;
  activeTab: Language;
  shareId: string | null;
  isSharing: boolean;

  setCode: (lang: Language, code: string) => void;
  setActiveTab: (tab: Language) => void;
  setShareId: (id: string | null) => void;
  setIsSharing: (v: boolean) => void;
  loadFromShare: (data: { html: string; css: string; javascript: string }) => void;
}

export const usePlaygroundStore = create<PlaygroundState>((set) => ({
  html: DEFAULT_HTML,
  css: DEFAULT_CSS,
  javascript: DEFAULT_JS,
  activeTab: "html",
  shareId: null,
  isSharing: false,

  setCode: (lang, code) => set({ [lang]: code }),
  setActiveTab: (activeTab) => set({ activeTab }),
  setShareId: (shareId) => set({ shareId }),
  setIsSharing: (isSharing) => set({ isSharing }),
  loadFromShare: (data) =>
    set({
      html: data.html,
      css: data.css,
      javascript: data.javascript,
      shareId: null,
    }),
}));
