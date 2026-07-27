//! Oxide VPN terminal UI (unprivileged).
//!
//! Browses servers from the control plane and drives the privileged agent
//! (`oxide-agentd`) over its Unix socket to connect/disconnect and show live status.
//! The UI never needs root — all privileged work happens in the agent.

mod app;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use futures::StreamExt;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use app::{human_bytes, sparkline, App, LinkHealth};
use oxide_common::agent::{AgentRequest, AgentResponse, ConnPhase, TunnelStatus, DEFAULT_SOCKET};
use oxide_control_client::ControlClient;

/// Braille spinner frames for the "working" states (selecting / connecting / reconnecting).
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Parser)]
#[command(name = "oxide-tui", about = "Oxide VPN terminal UI")]
struct Cli {
    #[arg(long)]
    control_plane: String,
    /// Account number (create one with `oxide-client account`).
    #[arg(long)]
    account: String,
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut app = App::new(cli.control_plane, cli.account, cli.socket);
    refresh_servers(&mut app).await;
    refresh_status(&mut app).await;

    let mut terminal = ratatui::init();
    let res = run(&mut terminal, &mut app).await;
    ratatui::restore();
    res
}

async fn run(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(1000));
    // A faster tick just animates the spinner so "connecting…" feels alive.
    let mut anim = tokio::time::interval(Duration::from_millis(120));
    loop {
        terminal.draw(|f| draw(f, app))?;
        tokio::select! {
            _ = tick.tick() => refresh_status(app).await,
            _ = anim.tick() => app.tick_spinner(),
            ev = events.next() => match ev {
                Some(Ok(Event::Key(k))) if k.kind == KeyEventKind::Press => handle_key(app, k.code).await,
                Some(Err(_)) | None => break,
                _ => {}
            },
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

async fn handle_key(app: &mut App, code: KeyCode) {
    // While the filter input is active, keystrokes edit the search term.
    if app.filtering {
        match code {
            KeyCode::Esc => {
                app.filter.clear();
                app.filtering = false;
                app.clamp_selection();
            }
            KeyCode::Enter => app.filtering = false,
            KeyCode::Backspace => {
                app.filter.pop();
                app.clamp_selection();
            }
            KeyCode::Char(c) => {
                app.filter.push(c);
                app.clamp_selection();
            }
            _ => {}
        }
        return;
    }
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
        KeyCode::Char('r') => refresh_servers(app).await,
        KeyCode::Char('d') => disconnect(app).await,
        KeyCode::Char('n') => new_identity(app).await,
        KeyCode::Char('/') => app.filtering = true,
        KeyCode::Char('K') => {
            app.toggle_kill_switch();
            app.message = format!(
                "kill switch {} for next connect",
                if app.kill_switch { "ON" } else { "off" }
            );
        }
        KeyCode::Char('t') => {
            app.toggle_sort();
            app.message = if app.sort_by_latency {
                "sorted by latency".into()
            } else {
                "sorted by load".into()
            };
        }
        KeyCode::Char('p') => probe_latencies(app).await,
        KeyCode::Char('b') => quick_connect_best(app).await,
        KeyCode::Enter | KeyCode::Char('c') => connect_selected(app).await,
        _ => {}
    }
}

/// Measure latency to every visible server concurrently (a manual "TCP ping" sweep).
async fn probe_latencies(app: &mut App) {
    let targets: Vec<(String, String)> = app
        .visible()
        .iter()
        .map(|s| (s.id.clone(), s.endpoint.clone()))
        .collect();
    if targets.is_empty() {
        return;
    }
    app.message = format!("pinging {} servers…", targets.len());
    let probes = targets.into_iter().map(|(id, endpoint)| async move {
        let rtt = oxide_client_core::latency::tcp_ping(
            &endpoint,
            oxide_client_core::latency::DEFAULT_TIMEOUT,
        )
        .await;
        (id, rtt)
    });
    for (id, rtt) in futures::future::join_all(probes).await {
        app.set_latency(id, rtt);
    }
    app.message = "latency updated (press t to sort by it)".into();
}

/// Connect to the control plane's best (least-loaded) server — no manual pick needed.
async fn quick_connect_best(app: &mut App) {
    let req = AgentRequest::Connect {
        control_plane: app.cp_url.clone(),
        account: app.account.clone(),
        server: None, // let the agent/control plane auto-select the best server
        exit: None,
        country: None,
        kill_switch: app.kill_switch,
    };
    match agent_request(&app.socket, &req).await {
        Ok(AgentResponse::Ok) => app.message = "quick-connecting to best server…".into(),
        Ok(AgentResponse::Error { message }) => app.message = format!("connect failed: {message}"),
        Ok(_) => {}
        Err(e) => app.message = format!("agent unreachable: {e} (is oxide-agentd running?)"),
    }
    refresh_status(app).await;
}

async fn refresh_servers(app: &mut App) {
    match ControlClient::new(&app.cp_url)
        .list_servers(&app.account)
        .await
    {
        Ok(v) => {
            app.set_servers(v);
            app.message = format!("{} servers", app.servers.len());
        }
        Err(e) => app.message = format!("server list failed: {e}"),
    }
}

async fn connect_selected(app: &mut App) {
    let Some(id) = app.selected_server_id() else {
        app.message = "no server selected".into();
        return;
    };
    let req = AgentRequest::Connect {
        control_plane: app.cp_url.clone(),
        account: app.account.clone(),
        server: Some(id.clone()),
        exit: None,
        country: None,
        kill_switch: app.kill_switch,
    };
    match agent_request(&app.socket, &req).await {
        Ok(AgentResponse::Ok) => {
            app.message = format!(
                "connecting to {id}{}…",
                if app.kill_switch {
                    " (kill switch)"
                } else {
                    ""
                }
            )
        }
        Ok(AgentResponse::Error { message }) => app.message = format!("connect failed: {message}"),
        Ok(_) => {}
        Err(e) => app.message = format!("agent unreachable: {e} (is oxide-agentd running?)"),
    }
    refresh_status(app).await;
}

async fn refresh_status(app: &mut App) {
    match agent_request(&app.socket, &AgentRequest::Status).await {
        Ok(AgentResponse::Status(s)) => app.set_status(s),
        Ok(_) => {}
        // Agent not running / unreachable: show disconnected.
        Err(_) => app.set_status(TunnelStatus::default()),
    }
}

async fn disconnect(app: &mut App) {
    match agent_request(&app.socket, &AgentRequest::Disconnect).await {
        Ok(_) => app.message = "disconnected".into(),
        Err(e) => app.message = format!("agent unreachable: {e}"),
    }
    refresh_status(app).await;
}

/// Ask the agent for a new identity: rotate the device key and switch to a different exit.
async fn new_identity(app: &mut App) {
    match agent_request(&app.socket, &AgentRequest::NewIdentity).await {
        Ok(AgentResponse::Ok) => app.message = "new identity: switching exit…".into(),
        Ok(AgentResponse::Error { message }) => app.message = format!("new identity: {message}"),
        Ok(_) => {}
        Err(e) => app.message = format!("agent unreachable: {e}"),
    }
    refresh_status(app).await;
}

/// One request → one response over the agent's Unix socket.
async fn agent_request(socket: &PathBuf, req: &AgentRequest) -> Result<AgentResponse> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connecting to agent socket")?;
    let (read, mut write) = stream.into_split();
    write.write_all(req.to_line().as_bytes()).await?;
    let mut lines = BufReader::new(read).lines();
    let line = lines.next_line().await?.context("no response from agent")?;
    Ok(serde_json::from_str(&line)?)
}

fn draw(f: &mut Frame, app: &App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Min(0),
        Constraint::Length(3),
    ])
    .areas(f.area());

    draw_header(f, app, header);

    // --- body: server list (filtered + optionally latency-sorted) ---
    let visible = app.visible();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|s| {
            let loc = match (&s.country, &s.city) {
                (Some(c), Some(city)) => format!("{c}/{city}"),
                (Some(c), None) => c.clone(),
                _ => "-".into(),
            };
            let load = if s.capacity > 0 {
                format!("{}/{}", s.active_peers, s.capacity)
            } else {
                s.active_peers.to_string()
            };
            let health = if s.healthy { "●" } else { "×" };
            // Latency column: absent until probed, "—" if unreachable.
            let lat = match app.latency_of(&s.id) {
                None => String::new(),
                Some(rtt) => oxide_client_core::latency::format_latency(rtt),
            };
            ListItem::new(format!(
                "{:<12} {:<16} load {:<9} {:>7} {}",
                s.id, loc, load, lat, health
            ))
        })
        .collect();
    let sort = if app.sort_by_latency {
        "latency"
    } else {
        "load"
    };
    let title = if app.filter.is_empty() {
        format!(" Servers ({}) · by {sort} ", visible.len())
    } else {
        format!(
            " Servers ({}/{}) · filter \"{}\" · by {sort} ",
            visible.len(),
            app.servers.len(),
            app.filter
        )
    };
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut list_state = ListState::default();
    if !visible.is_empty() {
        list_state.select(Some(app.selected.min(visible.len() - 1)));
    }
    f.render_stateful_widget(list, body, &mut list_state);

    // --- footer: keys + last message ---
    let help = if app.filtering {
        "type to filter · Enter apply · Esc clear".to_string()
    } else {
        let ks = if app.kill_switch { "KS on" } else { "KS off" };
        format!(
            "Enter connect · b best · d disconnect · n new-id · / filter · p ping · t sort · K kill-switch [{ks}] · q quit"
        )
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                format!("  {help}"),
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::raw(format!("  {}", app.message))),
        ])
        .block(Block::default().borders(Borders::TOP)),
        footer,
    );
}

/// The status panel: title, a phase-aware status line, feature badges, and — when connected —
/// a live throughput sparkline for each direction.
fn draw_header(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let st = &app.status;
    let mut lines = vec![Line::from(Span::styled(
        "  Oxide VPN",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))];

    lines.push(status_line(app));

    // Feature badges (only meaningful once we have a connection).
    if st.phase != ConnPhase::Disconnected {
        lines.push(badge_line(st));
    } else {
        lines.push(Line::from(""));
    }

    // Throughput sparklines when connected.
    if st.connected {
        lines.push(throughput_line(
            "  ↑",
            &app.tx_rate,
            st.tx_bytes,
            Color::Green,
        ));
        lines.push(throughput_line(
            "  ↓",
            &app.rx_rate,
            st.rx_bytes,
            Color::Blue,
        ));
    }

    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::BOTTOM)),
        area,
    );
}

/// The phase-aware status line: a green dot when connected, an animated spinner while working,
/// a gray ring when idle.
fn status_line(app: &App) -> Line<'static> {
    let st = &app.status;
    let server = st.server_id.clone().unwrap_or_else(|| "?".into());
    match st.phase {
        ConnPhase::Disconnected => Line::from(Span::styled(
            "  ○ disconnected",
            Style::default().fg(Color::DarkGray),
        )),
        ConnPhase::Connected => {
            let (dot, dot_color) = match app.link_health() {
                LinkHealth::Live => ("●", Color::Green),
                LinkHealth::Stale => ("◐", Color::Yellow),
                LinkHealth::Unknown => ("○", Color::Gray),
            };
            let handshake = st
                .handshake_age_secs
                .map(|a| format!("  hs {a}s"))
                .unwrap_or_default();
            let exit = st
                .exit_id
                .as_ref()
                .map(|e| format!(" → {e}"))
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(
                    format!("  {dot} CONNECTED "),
                    Style::default().fg(dot_color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{server}{exit}  up {}s{handshake}", st.uptime_secs)),
            ])
        }
        working => {
            let frame = SPINNER[app.spinner % SPINNER.len()];
            Line::from(vec![
                Span::styled(
                    format!("  {frame} {} ", working.label().to_uppercase()),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(if server == "?" { String::new() } else { server }),
            ])
        }
    }
}

/// A row of colored capability badges for the current connection.
fn badge_line(st: &TunnelStatus) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];
    let transport = st.transport.clone().unwrap_or_else(|| "plain".into());
    let (t_color, t_text) = match transport.as_str() {
        "quic" => (Color::Cyan, "QUIC"),
        "mimic" => (Color::Cyan, "MIMIC"),
        "obfs" => (Color::Blue, "OBFS"),
        _ => (Color::DarkGray, "PLAIN"),
    };
    spans.push(badge(t_text, t_color, true));
    spans.push(badge("DAITA", Color::Magenta, st.daita));
    spans.push(badge("PQ", Color::Yellow, st.post_quantum));
    spans.push(badge("STEALTH", Color::Green, st.stealth));
    spans.push(badge("KILL", Color::Red, st.kill_switch));
    Line::from(spans)
}

/// A single badge: bright when `on`, dim when off, so the whole capability set is always visible.
fn badge(text: &str, color: Color, on: bool) -> Span<'static> {
    let style = if on {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Span::styled(format!("[{text}] "), style)
}

/// One throughput row: an arrow, a sparkline, and the cumulative byte count.
fn throughput_line(arrow: &str, rate: &[u64], total: u64, color: Color) -> Line<'static> {
    let last = rate.last().copied().unwrap_or(0);
    Line::from(vec![
        Span::styled(
            format!("{arrow} "),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(sparkline(rate), Style::default().fg(color)),
        Span::raw(format!(
            "  {}/s  ({} total)",
            human_bytes(last),
            human_bytes(total)
        )),
    ])
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    fn render(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        buffer_text(&terminal)
    }

    #[test]
    fn connected_header_shows_badges_and_throughput() {
        let mut app = App::new("http://cp".into(), "acct".into(), "/tmp/s".into());
        app.set_status(TunnelStatus {
            connected: true,
            phase: ConnPhase::Connected,
            server_id: Some("us-nyc-1".into()),
            uptime_secs: 42,
            tx_bytes: 10_000,
            rx_bytes: 20_000,
            handshake_age_secs: Some(3),
            transport: Some("quic".into()),
            daita: true,
            post_quantum: true,
            kill_switch: true,
            ..Default::default()
        });
        let text = render(&app);
        assert!(text.contains("CONNECTED"));
        assert!(text.contains("us-nyc-1"));
        assert!(text.contains("QUIC"));
        assert!(text.contains("DAITA"));
        assert!(text.contains("KILL"));
        assert!(text.contains("hs 3s")); // handshake age
    }

    #[test]
    fn connecting_header_shows_phase_label() {
        let mut app = App::new("http://cp".into(), "acct".into(), "/tmp/s".into());
        app.set_status(TunnelStatus {
            phase: ConnPhase::Connecting,
            server_id: Some("de-fra-2".into()),
            ..Default::default()
        });
        let text = render(&app);
        assert!(text.contains("CONNECTING"));
        assert!(text.contains("de-fra-2"));
    }

    #[test]
    fn disconnected_header_is_idle() {
        let app = App::new("http://cp".into(), "acct".into(), "/tmp/s".into());
        let text = render(&app);
        assert!(text.contains("disconnected"));
    }

    #[test]
    fn server_list_shows_filter_and_latency() {
        use oxide_common::api::ServerInfo;
        use std::time::Duration;
        let mut app = App::new("http://cp".into(), "acct".into(), "/tmp/s".into());
        let mk = |id: &str, country: &str| ServerInfo {
            id: id.into(),
            public_key: oxide_common::keys::public_from_secret(
                &oxide_common::keys::generate_secret(),
            ),
            endpoint: "1.2.3.4:51820".into(),
            country: Some(country.into()),
            city: None,
            active_peers: 3,
            capacity: 100,
            healthy: true,
            pq_public_key: None,
        };
        app.set_servers(vec![mk("us-nyc-1", "US"), mk("de-fra-2", "DE")]);
        app.set_latency("us-nyc-1".into(), Some(Duration::from_millis(24)));
        app.filter = "nyc".into();
        let text = render(&app);
        assert!(text.contains("us-nyc-1"));
        assert!(!text.contains("de-fra-2")); // filtered out
        assert!(text.contains("24ms")); // latency column
        assert!(text.contains("filter")); // title reflects the active filter
    }
}
