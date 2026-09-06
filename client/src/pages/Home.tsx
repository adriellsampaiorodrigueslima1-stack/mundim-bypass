import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Check,
  ChevronDown,
  CircleHelp,
  Command,
  ExternalLink,
  Gamepad2,
  Gauge,
  Globe2,
  LockKeyhole,
  Menu,
  Play,
  Radio,
  RotateCcw,
  Server,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TimerReset,
  Wifi,
  X,
  Zap,
} from "lucide-react";

const savedTargets = [
  { name: "Krunker", url: "https://krunker.io", tag: "FPS" },
  { name: "Minecraft Classic", url: "https://classic.minecraft.net", tag: "SANDBOX" },
  { name: "Shell Shockers", url: "https://shellshock.io", tag: "ACTION" },
];

const nodes = [
  { name: "São Paulo", code: "GRU-01", latency: "18ms", quality: "99.98%", x: "33%", y: "65%" },
  { name: "Miami", code: "MIA-02", latency: "42ms", quality: "99.95%", x: "20%", y: "42%" },
  { name: "Lisboa", code: "LIS-04", latency: "118ms", quality: "99.91%", x: "57%", y: "29%" },
];

function Metric({ value, label, accent = false }: { value: string; label: string; accent?: boolean }) {
  return (
    <div className="metric">
      <span className={accent ? "metric-value accent" : "metric-value"}>{value}</span>
      <span className="metric-label">{label}</span>
    </div>
  );
}

function Home() {
  const [target, setTarget] = useState("");
  const [selectedNode, setSelectedNode] = useState(nodes[0]);
  const [autoRoute, setAutoRoute] = useState(true);
  const [showMobileNav, setShowMobileNav] = useState(false);
  const [showNodes, setShowNodes] = useState(false);
  const [status, setStatus] = useState<"ready" | "checking" | "opened">("ready");
  const [pulse, setPulse] = useState(18);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setPulse((current) => {
        const next = current + (Math.random() > 0.65 ? 1 : -1);
        return Math.max(16, Math.min(24, next));
      });
    }, 2400);
    return () => window.clearInterval(interval);
  }, []);

  const targetLabel = useMemo(() => {
    if (!target) return "Cole uma URL para iniciar";
    try {
      return new URL(target.startsWith("http") ? target : `https://${target}`).hostname;
    } catch {
      return "URL personalizada";
    }
  }, [target]);

  const launchTarget = () => {
    if (!target.trim()) {
      setStatus("checking");
      window.setTimeout(() => setStatus("ready"), 900);
      return;
    }
    const normalized = target.startsWith("http") ? target : `https://${target}`;
    setStatus("opened");
    window.setTimeout(() => window.open(normalized, "_blank", "noopener,noreferrer"), 240);
  };

  const runLatencyCheck = () => {
    setStatus("checking");
    window.setTimeout(() => setStatus("ready"), 900);
  };

  return (
    <main className="app-shell">
      <div className="noise-layer" />
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <header className="topbar container">
        <a className="brand" href="#top" aria-label="bypassschool início">
          <span className="brand-mark"><Command size={17} strokeWidth={2.4} /></span>
          <span>bypass<span>school</span></span>
        </a>
        <nav className={showMobileNav ? "nav-links open" : "nav-links"} aria-label="Navegação principal">
          <a href="#launcher" onClick={() => setShowMobileNav(false)}>Launcher</a>
          <a href="#performance" onClick={() => setShowMobileNav(false)}>Performance</a>
          <a href="#network" onClick={() => setShowMobileNav(false)}>Network</a>
          <a href="#docs" onClick={() => setShowMobileNav(false)}>Docs <ArrowUpRight size={13} /></a>
        </nav>
        <div className="topbar-actions">
          <div className="online-pill"><span className="status-dot" /> All systems nominal</div>
          <a className="icon-button" href="#docs" aria-label="Ajuda"><CircleHelp size={17} /></a>
          <button className="mobile-toggle" onClick={() => setShowMobileNav(!showMobileNav)} aria-label="Abrir menu">
            {showMobileNav ? <X size={21} /> : <Menu size={21} />}
          </button>
        </div>
      </header>

      <section className="hero container" id="top">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-line" /> LOW-LATENCY WEB GATEWAY <Sparkles size={14} /></div>
          <h1>Play the web.<br /><em>On your terms.</em></h1>
          <p className="hero-description">Um launcher ultrarrápido para experiências web interativas. Menos atrito, mais controle e uma conexão pronta para jogar.</p>
          <div className="hero-cta-row">
            <a className="text-cta" href="#launcher">Abrir launcher <ArrowUpRight size={16} /></a>
            <span className="micro-note"><ShieldCheck size={14} /> Sem instalação</span>
          </div>
        </div>

        <div className="signal-orbit" aria-hidden="true">
          <div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="orbit orbit-three" />
          <div className="orbit-core"><Zap size={27} fill="currentColor" /></div>
          <span className="orbit-label orbit-label-one">LOW LATENCY</span>
          <span className="orbit-label orbit-label-two">EDGE READY</span>
          <span className="orbit-label orbit-label-three">01 / 03</span>
        </div>
      </section>

      <section className="launcher-wrap container" id="launcher">
        <div className="section-kicker"><span>01</span> QUICK LAUNCH <span className="kicker-rule" /></div>
        <div className="launcher-grid">
          <div className="launch-card glass-card">
            <div className="card-topline">
              <div className="card-title"><span className="title-icon"><Gamepad2 size={18} /></span><div><span className="card-overline">SESSION STARTER</span><h2>Launch a game</h2></div></div>
              <div className="live-badge"><Radio size={12} /> LIVE</div>
            </div>
            <p className="card-description">Insira o endereço de um jogo web autorizado e abra uma sessão otimizada no seu navegador.</p>
            <div className="url-input-wrap">
              <Globe2 size={17} />
              <input value={target} onChange={(event) => { setTarget(event.target.value); setStatus("ready"); }} placeholder="https://seu-jogo-web.com" aria-label="URL do jogo" />
              {target && <button className="clear-input" onClick={() => setTarget("")} aria-label="Limpar URL"><X size={15} /></button>}
              <button className="launch-button" onClick={launchTarget} disabled={status === "checking"}>
                {status === "checking" ? <RotateCcw className="spin" size={16} /> : status === "opened" ? <Check size={16} /> : <Play size={15} fill="currentColor" />}
                <span>{status === "checking" ? "Verificando" : status === "opened" ? "Aberto" : "Launch"}</span>
              </button>
            </div>
            <div className="input-meta"><span>Destino detectado: <strong>{targetLabel}</strong></span><span><LockKeyhole size={12} /> browser-only</span></div>
            <div className="suggestions">
              <span className="suggestion-label">QUICK ACCESS</span>
              {savedTargets.map((item) => <button key={item.name} className="suggestion" onClick={() => setTarget(item.url)}><span>{item.name}</span><span>{item.tag}</span></button>)}
            </div>
          </div>

          <aside className="config-card glass-card">
            <div className="card-topline"><div className="card-title"><span className="title-icon muted"><SlidersHorizontal size={17} /></span><div><span className="card-overline">ROUTE CONFIG</span><h2>Session profile</h2></div></div><Settings2 size={17} className="muted-icon" /></div>
            <div className="config-row"><div><span className="config-label">EDGE NODE</span><strong>{selectedNode.name}</strong></div><button className="select-trigger" onClick={() => setShowNodes(!showNodes)} aria-expanded={showNodes}>{selectedNode.code}<ChevronDown size={15} /></button></div>
            {showNodes && <div className="node-menu">{nodes.map((node) => <button key={node.code} className={node.code === selectedNode.code ? "node-option selected" : "node-option"} onClick={() => { setSelectedNode(node); setShowNodes(false); }}><span><strong>{node.name}</strong><small>{node.code}</small></span><span>{node.latency}</span></button>)}</div>}
            <div className="config-row"><div><span className="config-label">SMART ROUTING</span><strong>Auto-select fastest</strong></div><button className={autoRoute ? "toggle on" : "toggle"} onClick={() => setAutoRoute(!autoRoute)} aria-label="Alternar roteamento automático"><span /></button></div>
            <div className="config-row"><div><span className="config-label">CACHE MODE</span><strong>Game assets · aggressive</strong></div><span className="config-status"><Check size={13} /> active</span></div>
            <div className="config-footer"><span><Wifi size={13} /> {pulse}ms median</span><span className="sparkline"><i /><i /><i /><i /><i /><i /><i /></span></div>
          </aside>
        </div>
      </section>

      <section className="metrics-strip container" id="performance">
        <Metric value="18ms" label="MEDIAN LATENCY" accent /><Metric value="99.98%" label="EDGE UPTIME" /><Metric value="3.4×" label="FASTER START" /><Metric value="24/7" label="NETWORK WATCH" />
      </section>

      <section className="lower-grid container">
        <div className="performance-card glass-card">
          <div className="section-heading"><div><div className="section-kicker"><span>02</span> PERFORMANCE <span className="kicker-rule" /></div><h2>Built for the <em>moment</em> between click and play.</h2></div><button className="round-action" onClick={runLatencyCheck} aria-label="Atualizar latência"><TimerReset size={17} /></button></div>
          <div className="chart-area"><div className="chart-ylabels"><span>40</span><span>30</span><span>20</span><span>10</span><span>0</span></div><div className="chart-grid"><div className="chart-line line-one" /><div className="chart-line line-two" /><div className="chart-line line-three" /><svg viewBox="0 0 500 160" preserveAspectRatio="none" role="img" aria-label="Gráfico de latência estável"><defs><linearGradient id="area" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#28b8ff" stopOpacity=".32" /><stop offset="1" stopColor="#28b8ff" stopOpacity="0" /></linearGradient></defs><path d="M0 118 C35 110 42 96 73 105 S119 91 140 98 S174 107 198 89 S236 69 259 82 S294 83 314 63 S348 81 370 65 S404 76 430 50 S465 58 500 36 L500 160 L0 160 Z" fill="url(#area)" /><path className="chart-path" d="M0 118 C35 110 42 96 73 105 S119 91 140 98 S174 107 198 89 S236 69 259 82 S294 83 314 63 S348 81 370 65 S404 76 430 50 S465 58 500 36" fill="none" stroke="#53c9ff" strokeWidth="2.5" /></svg></div></div><div className="chart-footer"><span>Last 30 minutes</span><span><span className="chart-live-dot" /> live telemetry</span></div>
        </div>

        <div className="network-card glass-card" id="network">
          <div className="section-kicker"><span>03</span> NETWORK STATUS <span className="kicker-rule" /></div>
          <div className="network-map"><div className="map-grid" /><div className="map-line map-line-one" /><div className="map-line map-line-two" />{nodes.map((node) => <div key={node.code} className="map-node" style={{ left: node.x, top: node.y }}><span className="node-pulse" /><span className="node-tooltip">{node.name} · {node.latency}</span></div>)}</div>
          <div className="node-list">{nodes.map((node) => <button key={node.code} className="node-list-row" onClick={() => { setSelectedNode(node); document.getElementById("launcher")?.scrollIntoView({ behavior: "smooth" }); }}><span className="node-name"><span className="status-dot" />{node.name}<small>{node.code}</small></span><span className="node-quality">{node.latency} <small>{node.quality}</small></span><ArrowUpRight size={14} /></button>)}</div>
        </div>
      </section>

      <section className="principles container" id="docs">
        <div className="principle"><Gauge size={19} /><div><strong>Performance-first</strong><span>Interface enxuta, pronta para resposta rápida.</span></div></div>
        <div className="principle"><Server size={19} /><div><strong>Edge-aware</strong><span>Escolha o nó mais próximo da sua sessão.</span></div></div>
        <div className="principle"><ShieldCheck size={19} /><div><strong>Responsible by design</strong><span>Use apenas com destinos autorizados.</span></div></div>
        <div className="principle"><Activity size={19} /><div><strong>Observable</strong><span>Métricas claras, sem promessas mágicas.</span></div></div>
      </section>

      <footer className="footer container"><span>© 2026 bypassschool</span><span className="footer-center"><span className="status-dot" /> all systems nominal</span><span>v0.1.0 / preview build</span></footer>
    </main>
  );
}

export default Home;
