/* ============================================
   أربكس الدردشة — تصميم احترافي v2.0
   Design Tokens + Modern UI
   ============================================ */

:root {
  /* الألوان الأساسية */
  --bg-0: #05070d;
  --bg-1: #0a0e1a;
  --bg-2: #111827;
  --bg-3: #1a2234;
  --bg-elev: #161e2e;
  
  /* العلامة التجارية */
  --brand-1: #6366f1;   /* Indigo */
  --brand-2: #8b5cf6;   /* Violet */
  --brand-3: #ec4899;   /* Pink */
  --brand-glow: rgba(99, 102, 241, 0.4);
  
  /* الألوان الوظيفية */
  --accent: #06b6d4;
  --success: #10b981;
  --warning: #f59e0b;
  --danger: #ef4444;
  
  /* النصوص */
  --text-1: #f8fafc;
  --text-2: #cbd5e1;
  --text-3: #94a3b8;
  --text-4: #64748b;
  
  /* الحدود والفواصل */
  --border-1: rgba(255, 255, 255, 0.06);
  --border-2: rgba(255, 255, 255, 0.1);
  --border-3: rgba(255, 255, 255, 0.15);
  
  /* الظلال */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.3);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.4);
  --shadow-lg: 0 12px 32px rgba(0, 0, 0, 0.5);
  --shadow-glow: 0 0 32px var(--brand-glow);
  
  /* الزوايا */
  --r-sm: 8px;
  --r-md: 12px;
  --r-lg: 16px;
  --r-xl: 24px;
  --r-full: 9999px;
  
  /* الانتقالات */
  --ease: cubic-bezier(0.4, 0, 0.2, 1);
  --ease-spring: cubic-bezier(0.34, 1.56, 0.64, 1);
  --t-fast: 150ms var(--ease);
  --t-base: 250ms var(--ease);
  --t-slow: 400ms var(--ease);
  
  /* الخطوط */
  --font-sans: 'Cairo', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  --font-display: 'Lalezar', 'Cairo', sans-serif;
  
  /* أحجام */
  --fs-base: 16px;
  --sidebar-w: 360px;
}

/* الثيمات الفرعية */
html[data-theme="girls"] {
  --brand-1: #ec4899; --brand-2: #f472b6; --brand-3: #fb7185;
  --accent: #a78bfa;
  --brand-glow: rgba(236, 72, 153, 0.4);
}
html[data-theme="boys"] {
  --brand-1: #3b82f6; --brand-2: #06b6d4; --brand-3: #0ea5e9;
  --accent: #22d3ee;
  --brand-glow: rgba(59, 130, 246, 0.4);
}
html[data-theme="disco"] {
  --brand-1: #ff00e6; --brand-2: #00fff0; --brand-3: #fff700;
  --accent: #7a00ff;
  --brand-glow: rgba(255, 0, 230, 0.5);
}
html[data-theme="hacker"] {
  --bg-0: #000; --bg-1: #000; --bg-2: #0a0a0a; --bg-3: #111;
  --brand-1: #00ff41; --brand-2: #39ff14; --brand-3: #00ff41;
  --accent: #00ff41;
  --text-1: #b6ffb6;
  --font-sans: 'Courier New', monospace;
  --brand-glow: rgba(0, 255, 65, 0.4);
}

/* ============================================
   Reset & Base
   ============================================ */
*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }

html {
  font-size: var(--fs-base);
  -webkit-text-size-adjust: 100%;
  scroll-behavior: smooth;
}

body {
  margin: 0;
  min-height: 100dvh;
  background: var(--bg-0);
  color: var(--text-1);
  font-family: var(--font-sans);
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  overflow-x: hidden;
}

a { color: var(--accent); text-decoration: none; transition: color var(--t-fast); }
a:hover { color: var(--brand-2); }

button { font-family: inherit; cursor: pointer; border: none; background: none; }
input, select, textarea { font-family: inherit; }

/* Focus */
:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: 4px;
}

/* Scrollbar */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb {
  background: var(--border-3);
  border-radius: var(--r-full);
}
::-webkit-scrollbar-thumb:hover { background: var(--text-4); }

/* ============================================
   Animated Background
   ============================================ */
.bg {
  position: fixed;
  inset: 0;
  z-index: -1;
  overflow: hidden;
  background: radial-gradient(ellipse at top, var(--bg-2) 0%, var(--bg-0) 60%);
}
.bg::before,
.bg::after {
  content: '';
  position: absolute;
  width: 60vmax;
  height: 60vmax;
  border-radius: 50%;
  filter: blur(120px);
  opacity: 0.35;
  animation: auroraFloat 24s ease-in-out infinite alternate;
}
.bg::before {
  background: var(--brand-1);
  top: -25%; right: -20%;
}
.bg::after {
  background: var(--brand-3);
  bottom: -30%; left: -20%;
  animation-delay: -12s;
}
html[data-theme="disco"] .bg::before,
html[data-theme="disco"] .bg::after {
  animation: auroraFloat 24s ease-in-out infinite alternate, hueShift 8s linear infinite;
}

@keyframes auroraFloat {
  to { transform: translate(10vmax, -8vmax) scale(1.2); }
}
@keyframes hueShift {
  to { filter: blur(120px) hue-rotate(360deg); }
}

/* ============================================
   Landing / Login Page
   ============================================ */
.hero {
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 20px;
  text-align: center;
  gap: 8px;
}

.logo {
  width: 120px;
  height: 120px;
  margin-bottom: 8px;
  filter: drop-shadow(0 0 40px var(--brand-glow));
  animation: logoFloat 5s ease-in-out infinite alternate;
}
@keyframes logoFloat {
  to { transform: translateY(-10px) rotate(2deg); }
}

.kicker {
  margin: 0;
  font-size: 0.875rem;
  font-weight: 600;
  letter-spacing: 0.3em;
  color: var(--accent);
  text-transform: uppercase;
}

h1 {
  font-family: var(--font-display);
  font-size: clamp(3rem, 12vw, 6rem);
  line-height: 1;
  margin: 8px 0 12px;
  background: linear-gradient(100deg, var(--brand-1), var(--brand-2), var(--brand-3), var(--brand-1));
  background-size: 300% 100%;
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  animation: gradientShift 8s linear infinite;
}
@keyframes gradientShift {
  to { background-position: -300% 0; }
}

.by {
  margin: 0 0 8px;
  font-size: 1rem;
  color: var(--text-2);
}
.by a {
  color: var(--brand-3);
  font-weight: 700;
  border-bottom: 1px dashed transparent;
  transition: border-color var(--t-fast);
}
.by a:hover { border-bottom-color: var(--brand-3); }

.sub {
  font-size: 1.125rem;
  margin: 0 0 24px;
  color: var(--text-3);
  max-width: 480px;
}

.ig {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 14px 32px;
  border-radius: var(--r-full);
  background: linear-gradient(135deg, var(--brand-3), #f97316);
  color: #fff;
  font-weight: 700;
  box-shadow: 0 10px 40px rgba(236, 72, 153, 0.4);
  transition: transform var(--t-base), box-shadow var(--t-base);
  margin-bottom: 16px;
}
.ig:hover {
  transform: translateY(-2px) scale(1.02);
  box-shadow: 0 16px 48px rgba(236, 72, 153, 0.55);
  color: #fff;
}

.links {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  justify-content: center;
  margin-bottom: 20px;
}
.links a {
  padding: 8px 20px;
  border-radius: var(--r-full);
  border: 1px solid var(--border-2);
  background: rgba(255, 255, 255, 0.03);
  color: var(--text-2);
  font-weight: 600;
  font-size: 0.875rem;
  transition: all var(--t-base);
}
.links a:hover {
  border-color: var(--accent);
  color: var(--accent);
  background: rgba(6, 182, 212, 0.08);
  transform: translateY(-2px);
}

/* Glass Card */
.glass {
  width: min(420px, 100%);
  padding: 28px;
  background: rgba(22, 30, 46, 0.6);
  backdrop-filter: blur(24px) saturate(180%);
  -webkit-backdrop-filter: blur(24px) saturate(180%);
  border: 1px solid var(--border-2);
  border-radius: var(--r-xl);
  box-shadow: var(--shadow-lg), inset 0 1px 0 rgba(255, 255, 255, 0.05);
  margin-top: 8px;
  animation: fadeInUp 600ms var(--ease-spring) backwards;
}
@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(20px); }
}

.glass form { margin: 0; }

/* Tabs */
.tabs {
  display: flex;
  gap: 4px;
  padding: 4px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: var(--r-md);
  margin-bottom: 20px;
}
.tab {
  flex: 1;
  padding: 10px 16px;
  border-radius: var(--r-sm);
  background: transparent;
  color: var(--text-3);
  font-weight: 600;
  font-size: 0.95rem;
  transition: all var(--t-base);
}
.tab:hover { color: var(--text-1); background: rgba(255, 255, 255, 0.05); }
.tab.on {
  background: linear-gradient(135deg, var(--brand-1), var(--brand-2));
  color: #fff;
  box-shadow: 0 4px 12px var(--brand-glow);
}

/* Inputs */
input, select, textarea {
  width: 100%;
  padding: 14px 16px;
  margin-bottom: 12px;
  border-radius: var(--r-md);
  border: 1px solid var(--border-2);
  background: rgba(10, 14, 26, 0.7);
  color: var(--text-1);
  font-size: 0.95rem;
  transition: all var(--t-base);
}
input::placeholder, textarea::placeholder { color: var(--text-4); }
input:focus, select:focus, textarea:focus {
  border-color: var(--brand-1);
  background: rgba(10, 14, 26, 0.9);
  box-shadow: 0 0 0 3px var(--brand-glow);
  outline: none;
}
input[type="checkbox"], input[type="color"] { width: auto; margin: 0; }
input[type="color"] {
  height: 42px;
  padding: 4px;
  cursor: pointer;
  vertical-align: middle;
}

textarea { resize: vertical; min-height: 80px; }
select option { background: var(--bg-2); color: var(--text-1); }

/* Checkbox */
.chk {
  display: flex;
  gap: 10px;
  align-items: center;
  padding: 12px 14px;
  margin-bottom: 14px;
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid var(--border-1);
  border-radius: var(--r-md);
  font-size: 0.9rem;
  color: var(--text-2);
  cursor: pointer;
  transition: border-color var(--t-fast);
}
.chk:hover { border-color: var(--border-3); }
.chk input { width: auto; margin: 0; accent-color: var(--brand-1); }

/* Buttons */
button:not(.lnk):not(.tab):not(.sw):not(#dot):not(.more summary) {
  padding: 12px 24px;
  border-radius: var(--r-md);
  background: linear-gradient(135deg, var(--brand-1), var(--brand-2));
  color: #fff;
  font-weight: 700;
  font-size: 0.95rem;
  box-shadow: 0 4px 14px var(--brand-glow);
  transition: all var(--t-base);
  position: relative;
  overflow: hidden;
}
button:not(.lnk):not(.tab):not(.sw):not(#dot):not(.more summary):hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px var(--brand-glow);
  filter: brightness(1.1);
}
button:not(.lnk):not(.tab):not(.sw):not(#dot):not(.more summary):active {
  transform: translateY(0);
}
button.alt {
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-1);
  box-shadow: none;
  border: 1px solid var(--border-2);
}
button.alt:hover {
  background: rgba(255, 255, 255, 0.1);
  box-shadow: none;
  filter: none;
}
button.lnk {
  background: none;
  color: var(--accent);
  padding: 8px;
  font-size: 0.875rem;
  font-weight: 600;
  text-decoration: none;
  box-shadow: none;
}
button.lnk:hover { color: var(--brand-2); text-decoration: underline; }

/* Status messages */
p[role="status"] {
  min-height: 1.4em;
  margin: 8px 0 0;
  font-size: 0.875rem;
  transition: color var(--t-fast);
}
.good { color: var(--success); }
.bad { color: var(--danger); }
.hintp {
  font-size: 0.8rem;
  color: var(--text-4);
  margin: 8px 0 0;
}

/* ============================================
   App Layout
   ============================================ */
#app {
  display: grid;
  grid-template-columns: var(--sidebar-w) 1fr;
  height: 100dvh;
  overflow: hidden;
}

body.in footer { display: none; }

/* Sidebar */
aside {
  display: flex;
  flex-direction: column;
  min-height: 0;
  background: linear-gradient(180deg, var(--bg-1), var(--bg-0));
  border-inline-end: 1px solid var(--border-1);
  padding: 12px;
  gap: 8px;
}

.top {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.brand {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 10px;
  font-family: var(--font-display);
  font-size: 1.5rem;
  color: var(--text-1);
}
.brand img {
  filter: drop-shadow(0 0 12px var(--brand-glow));
}
.brand span {
  background: linear-gradient(135deg, var(--brand-1), var(--brand-3));
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}

.top button {
  padding: 8px 14px;
  font-size: 0.8rem;
  border-radius: var(--r-sm);
  background: rgba(255, 255, 255, 0.05);
  color: var(--text-2);
  box-shadow: none;
  border: 1px solid var(--border-1);
}
.top button:hover {
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-1);
  transform: none;
  box-shadow: none;
}

/* Me button */
.meb {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  padding: 10px 14px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid var(--border-1);
  border-radius: var(--r-md);
  color: var(--text-1);
  text-align: start;
  transition: all var(--t-base);
  box-shadow: none;
}
.meb:hover {
  background: rgba(255, 255, 255, 0.06);
  border-color: var(--border-3);
  transform: none;
  box-shadow: none;
}
.meb b { font-size: 0.95rem; }

#onc {
  font-size: 0.8rem;
  color: var(--success);
  padding: 4px 8px;
  display: flex;
  align-items: center;
  gap: 6px;
}
#onc::before {
  content: '';
  width: 6px; height: 6px;
  background: var(--success);
  border-radius: 50%;
  box-shadow: 0 0 8px var(--success);
  animation: pulse 2s infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

/* Search */
#q {
  margin: 0;
  padding: 12px 16px;
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid var(--border-1);
  border-radius: var(--r-md);
  font-size: 0.9rem;
}
#q:focus {
  border-color: var(--brand-1);
  box-shadow: 0 0 0 3px var(--brand-glow);
}

.pane {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
#list, #slist {
  overflow-y: auto;
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding-inline-end: 4px;
}

/* Member item */
.mem {
  display: flex;
  gap: 12px;
  align-items: center;
  padding: 10px 12px;
  border-radius: var(--r-md);
  cursor: pointer;
  transition: all var(--t-fast);
  position: relative;
}
.mem:hover { background: rgba(255, 255, 255, 0.05); }
.mem.act {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(139, 92, 246, 0.1));
  border: 1px solid rgba(99, 102, 241, 0.3);
}

.mt { flex: 1; min-width: 0; }
.mt b {
  display: block;
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text-1);
  margin-bottom: 2px;
}
.mt small {
  display: block;
  font-size: 0.8rem;
  color: var(--text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Avatar */
.av {
  display: inline-grid;
  place-items: center;
  border-radius: 50%;
  overflow: hidden;
  color: #fff;
  font-weight: 700;
  flex: none;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}
.av img { width: 100%; height: 100%; object-fit: cover; }
.avw {
  position: relative;
  flex: none;
  display: inline-flex;
}
.avw .dot {
  position: absolute;
  bottom: 0;
  inset-inline-end: 0;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--text-4);
  border: 2px solid var(--bg-1);
}
.avw .dot.on {
  background: var(--success);
  box-shadow: 0 0 12px var(--success);
}

/* Badge */
.bdg {
  min-width: 22px;
  height: 22px;
  padding: 0 8px;
  background: linear-gradient(135deg, var(--brand-3), #f97316);
  border-radius: var(--r-full);
  color: #fff;
  font-size: 0.75rem;
  font-weight: 700;
  display: grid;
  place-items: center;
  box-shadow: 0 2px 8px rgba(236, 72, 153, 0.5);
}

.mut {
  color: var(--text-4);
  text-align: center;
  margin: 32px 16px;
  font-size: 0.9rem;
}

/* Sidebar links */
.slinks {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  padding-top: 10px;
  margin-top: 4px;
  border-top: 1px solid var(--border-1);
  font-size: 0.75rem;
}
.slinks a {
  color: var(--text-4);
  transition: color var(--t-fast);
}
.slinks a:hover { color: var(--accent); }

/* ============================================
   Chat Area
   ============================================ */
#chat {
  display: flex;
  flex-direction: column;
  min-height: 0;
  background: var(--bg-1);
  position: relative;
}

#chat[data-bg="1"] {
  background-image: linear-gradient(160deg, rgba(99, 102, 241, 0.05), rgba(236, 72, 153, 0.08) 60%, rgba(6, 182, 212, 0.05));
}
#chat[data-bg="2"] {
  background-image: radial-gradient(rgba(255, 255, 255, 0.08) 1.5px, transparent 1.5px);
  background-size: 24px 24px;
}
#chat[data-bg="3"] {
  background-image:
    linear-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.04) 1px, transparent 1px);
  background-size: 32px 32px;
}
#chat[data-bg="4"] {
  background-image:
    radial-gradient(2px 2px at 20px 30px, rgba(255, 255, 255, 0.6), transparent),
    radial-gradient(1.5px 1.5px at 90px 80px, rgba(255, 255, 255, 0.5), transparent),
    radial-gradient(2px 2px at 160px 40px, rgba(255, 200, 61, 0.8), transparent),
    radial-gradient(1.5px 1.5px at 60px 140px, rgba(6, 182, 212, 0.6), transparent);
  background-size: 200px 180px;
}
#chat[data-bg="5"] {
  background-image: repeating-linear-gradient(45deg, rgba(255, 255, 255, 0.03) 0 12px, transparent 12px 24px);
}

#hint {
  margin: auto;
  color: var(--text-4);
  font-size: 1rem;
  text-align: center;
  padding: 24px;
}

#cbox {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
}

/* Chat header */
.chead {
  display: flex;
  gap: 12px;
  align-items: center;
  padding: 12px 16px;
  background: rgba(10, 14, 26, 0.85);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border-1);
  z-index: 10;
}
.chead button {
  padding: 8px 14px;
  font-size: 0.85rem;
  border-radius: var(--r-sm);
  background: rgba(255, 255, 255, 0.05);
  color: var(--text-2);
  box-shadow: none;
  border: 1px solid var(--border-1);
}
.chead button:hover {
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-1);
  transform: none;
  box-shadow: none;
}

.cn {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  line-height: 1.3;
}
.cn b {
  font-size: 1rem;
  font-weight: 700;
  color: var(--text-1);
}
.cn small {
  font-size: 0.8rem;
  color: var(--text-4);
  transition: color var(--t-fast);
}
.cn small.ok {
  color: var(--success);
  display: flex;
  align-items: center;
  gap: 4px;
}
.cn small.ok::before {
  content: '';
  width: 6px; height: 6px;
  background: var(--success);
  border-radius: 50%;
  box-shadow: 0 0 8px var(--success);
}

.more { position: relative; }
.more summary {
  list-style: none;
  cursor: pointer;
  padding: 8px 14px;
  border-radius: var(--r-sm);
  background: rgba(255, 255, 255, 0.05);
  color: var(--text-2);
  font-weight: 600;
  font-size: 0.85rem;
  border: 1px solid var(--border-1);
  transition: all var(--t-fast);
}
.more summary::-webkit-details-marker { display: none; }
.more summary:hover {
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-1);
}
.more > div {
  position: absolute;
  inset-inline-end: 0;
  top: calc(100% + 6px);
  background: var(--bg-elev);
  border: 1px solid var(--border-2);
  border-radius: var(--r-md);
  padding: 6px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 140px;
  z-index: 20;
  box-shadow: var(--shadow-lg);
  animation: fadeInUp 200ms var(--ease);
}
.more > div button {
  width: 100%;
  text-align: start;
  padding: 10px 14px;
  font-size: 0.85rem;
  border-radius: var(--r-sm);
  background: transparent;
  color: var(--text-2);
  box-shadow: none;
  border: none;
}
.more > div button:hover {
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-1);
  transform: none;
  box-shadow: none;
}

/* Messages */
#msgs {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  scroll-behavior: smooth;
}

.m {
  max-width: 75%;
  padding: 10px 16px;
  border-radius: 20px;
  background: var(--bg-3);
  color: var(--text-1);
  align-self: flex-start;
  border-end-start-radius: 6px;
  overflow-wrap: anywhere;
  font-size: 0.95rem;
  line-height: 1.5;
  box-shadow: var(--shadow-sm);
  animation: messageIn 250ms var(--ease-spring);
}
@keyframes messageIn {
  from { opacity: 0; transform: translateY(8px) scale(0.96); }
}
.m.me {
  align-self: flex-end;
  background: linear-gradient(135deg, var(--brand-1), var(--brand-2));
  color: #fff;
  border-end-start-radius: 20px;
  border-end-end-radius: 6px;
}
.m small.t {
  display: block;
  opacity: 0.6;
  font-size: 0.7rem;
  margin-top: 4px;
  text-align: end;
}

.pic {
  max-width: 100%;
  max-height: 320px;
  border-radius: var(--r-md);
  display: block;
}
.vid {
  max-width: 100%;
  max-height: 360px;
  border-radius: var(--r-md);
  display: block;
}
.m audio {
  width: 260px;
  max-width: 100%;
  display: block;
}

/* Typing indicator */
#typing {
  margin: 0;
  padding: 4px 20px 8px;
  color: var(--text-3);
  font-size: 0.85rem;
  display: flex;
  align-items: center;
  gap: 6px;
}
#typing::after {
  content: '';
  display: inline-flex;
  gap: 3px;
}
#typing::before {
  content: '';
  width: 8px; height: 8px;
  background: var(--accent);
  border-radius: 50%;
  animation: typing 1.4s infinite;
}
@keyframes typing {
  0%, 60%, 100% { opacity: 0.3; transform: translateY(0); }
  30% { opacity: 1; transform: translateY(-3px); }
}

/* Send bar */
#send {
  display: flex;
  gap: 8px;
  padding: 12px 16px;
  align-items: center;
  background: rgba(10, 14, 26, 0.85);
  backdrop-filter: blur(16px);
  border-top: 1px solid var(--border-1);
}
#send input {
  margin: 0;
  padding: 12px 20px;
  border-radius: var(--r-full);
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid var(--border-1);
  font-size: 0.95rem;
}
#send input:focus {
  border-color: var(--brand-1);
  box-shadow: 0 0 0 3px var(--brand-glow);
}
#send button, .att {
  padding: 12px 18px;
  font-size: 0.85rem;
  white-space: nowrap;
  border-radius: var(--r-full);
}
.att {
  border-radius: var(--r-full);
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-2);
  cursor: pointer;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: 1px solid var(--border-1);
  transition: all var(--t-fast);
}
.att:hover {
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-1);
}
#rec {
  background: rgba(255, 255, 255, 0.06);
  color: var(--text-2);
  box-shadow: none;
  border: 1px solid var(--border-1);
}
#rec:hover {
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-1);
  transform: none;
  box-shadow: none;
}
#rec.on {
  background: linear-gradient(135deg, var(--danger), #dc2626);
  color: #fff;
  box-shadow: 0 4px 14px rgba(239, 68, 68, 0.4);
  border-color: transparent;
}

#back { display: none; }

/* Status cards */
.sc {
  border-radius: var(--r-lg);
  padding: 20px;
  margin: 6px 0;
  min-height: 110px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  color: #fff;
  text-shadow: 0 1px 4px rgba(0, 0, 0, 0.4);
  box-shadow: var(--shadow-md);
  transition: transform var(--t-base);
}
.sc:hover { transform: translateY(-2px); }
.stx {
  margin: 0 0 12px;
  font-size: 1.1rem;
  font-weight: 600;
  text-align: center;
  overflow-wrap: anywhere;
  line-height: 1.4;
}
.sf {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.8rem;
}
.sf small { margin-inline-start: auto; opacity: 0.9; }

.s0 { background: linear-gradient(135deg, #6366f1, #ec4899); }
.s1 { background: linear-gradient(135deg, #06b6d4, #8b5cf6); }
.s2 { background: linear-gradient(135deg, #f97316, #ec4899); }
.s3 { background: linear-gradient(135deg, #10b981, #059669); }
.s4 { background: linear-gradient(135deg, #f59e0b, #ea580c); }
.s5 { background: linear-gradient(135deg, #ec4899, #a855f7); }
.s6 { background: linear-gradient(135deg, #3b82f6, #06b6d4); }
.s7 { background: linear-gradient(135deg, #1f2937, #4b5563); }

.swr {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.sw {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  padding: 0;
  border: 3px solid transparent;
  cursor: pointer;
  transition: all var(--t-fast);
}
.sw:hover { transform: scale(1.1); }
.sw.on { border-color: #fff; box-shadow: 0 0 0 2px var(--brand-1); }

/* Call overlay */
#call {
  position: fixed;
  inset: 0;
  background: #000;
  z-index: 100;
}
#rv {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
#lv {
  position: absolute;
  width: 120px;
  bottom: 100px;
  left: 16px;
  border-radius: var(--r-md);
  box-shadow: var(--shadow-lg);
  border: 2px solid var(--border-2);
}
.cc {
  position: absolute;
  bottom: 24px;
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
}
.cc button {
  width: 56px;
  height: 56px;
  padding: 0;
  border-radius: 50%;
  font-size: 0.75rem;
  background: rgba(255, 255, 255, 0.15);
  color: #fff;
  backdrop-filter: blur(16px);
  border: 1px solid var(--border-2);
  box-shadow: none;
}
.cc button:hover {
  background: rgba(255, 255, 255, 0.25);
  transform: scale(1.05);
  box-shadow: none;
}
#end { background: linear-gradient(135deg, var(--danger), #dc2626); border-color: transparent; }

/* Row helper */
.row {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.row h3 {
  flex: 1;
  margin: 0;
  font-size: 1.1rem;
}

/* Footer */
footer {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  padding: 32px 20px;
  text-align: center;
  border-top: 1px solid var(--border-1);
  background: var(--bg-0);
}
.foot p {
  margin: 2px 0;
  font-size: 0.85rem;
  color: var(--text-3);
}
.foot a {
  color: var(--brand-2);
  font-weight: 600;
}
.foot a:hover { color: var(--brand-3); }
.foot .rules {
  color: var(--text-4);
  font-size: 0.75rem;
  max-width: 500px;
}
#dot {
  width: 10px;
  height: 10px;
  padding: 0;
  border-radius: 50%;
  background: var(--danger);
  opacity: 0.6;
  cursor: pointer;
  transition: opacity var(--t-fast);
}
#dot:hover { opacity: 1; }

/* ============================================
   Dialogs
   ============================================ */
dialog {
  border: 1px solid var(--border-2);
  border-radius: var(--r-xl);
  background: var(--bg-elev);
  color: var(--text-1);
  width: min(680px, 94vw);
  max-height: 90dvh;
  padding: 24px;
  box-shadow: var(--shadow-lg);
  animation: dialogIn 300ms var(--ease-spring);
}
@keyframes dialogIn {
  from { opacity: 0; transform: scale(0.95) translateY(10px); }
}
dialog::backdrop {
  background: rgba(0, 0, 0, 0.7);
  backdrop-filter: blur(8px);
  animation: fadeIn 300ms var(--ease);
}
@keyframes fadeIn {
  from { opacity: 0; }
}

#st, #stc { width: min(480px, 94vw); }
#st h4 {
  margin: 20px 0 10px;
  color: var(--brand-2);
  font-size: 1rem;
  font-weight: 700;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border-1);
}
#st h4:first-of-type { margin-top: 8px; }
#st label {
  display: block;
  margin-bottom: 6px;
  font-size: 0.85rem;
  color: var(--text-2);
  font-weight: 600;
}

#xf {
  text-align: center;
  width: min(400px, 94vw);
}
#xcode {
  display: block;
  font-size: 2.5rem;
  letter-spacing: 0.4em;
  color: var(--brand-3);
  margin: 16px 0;
  font-weight: 700;
  font-family: 'Courier New', monospace;
}

/* Admin panel */
.scroll {
  overflow: auto;
  max-height: 40dvh;
  border: 1px solid var(--border-1);
  border-radius: var(--r-md);
  margin-bottom: 12px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}
td, th {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border-1);
  text-align: start;
}
th {
  background: rgba(255, 255, 255, 0.03);
  font-weight: 700;
  color: var(--text-2);
  position: sticky;
  top: 0;
  backdrop-filter: blur(8px);
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255, 255, 255, 0.02); }
td button {
  padding: 4px 12px;
  font-size: 0.75rem;
  margin-inline-start: 4px;
  border-radius: var(--r-sm);
}

/* ============================================
   Responsive
   ============================================ */
@media (max-width: 768px) {
  :root { --sidebar-w: 100%; }
  
  #app { grid-template-columns: 1fr; }
  
  body.chatting aside { display: none; }
  body:not(.chatting) #chat { display: none; }
  
  #back { display: inline-flex; }
  
  .m { max-width: 85%; }
  
  .hero { padding: 32px 16px; }
  .logo { width: 100px; height: 100px; }
  
  .glass { padding: 20px; }
  
  .chead { padding: 10px 12px; gap: 8px; }
  .chead button { padding: 6px 10px; font-size: 0.8rem; }
  
  #msgs { padding: 12px; }
  #send { padding: 8px 12px; gap: 6px; }
  #send button, .att { padding: 10px 14px; font-size: 0.8rem; }
  
  dialog { padding: 18px; }
}

@media (max-width: 480px) {
  #send .att { padding: 10px; }
  #send .att span { display: none; }
  #rec { padding: 10px; }
}

/* ============================================
   Accessibility
   ============================================ */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
  h1 {
    background: var(--brand-2);
    -webkit-background-clip: text;
    background-clip: text;
  }
}

/* Selection */
::selection {
  background: var(--brand-1);
  color: #fff;
}
