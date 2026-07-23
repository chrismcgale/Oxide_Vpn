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

use app::{human_bytes, App};
use oxide_common::agent::{AgentRequest, AgentResponse, TunnelStatus, DEFAULT_SOCKET};
use oxide_control_client::ControlClient;

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
    loop {
        terminal.draw(|f| draw(f, app))?;
        tokio::select! {
            _ = tick.tick() => refresh_status(app).await,
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
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
        KeyCode::Char('r') => refresh_servers(app).await,
        KeyCode::Char('d') => disconnect(app).await,
        KeyCode::Char('n') => new_identity(app).await,
        KeyCode::Enter | KeyCode::Char('c') => connect_selected(app).await,
        _ => {}
    }
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

async fn refresh_status(app: &mut App) {
    match agent_request(&app.socket, &AgentRequest::Status).await {
        Ok(AgentResponse::Status(s)) => app.set_status(s),
        Ok(_) => {}
        // Agent not running / unreachable: show disconnected.
        Err(_) => app.set_status(TunnelStatus::default()),
    }
}

async fn connect_selected(app: &mut App) {
    let Some(server) = app.selected_server() else {
        app.message = "no server selected".into();
        return;
    };
    let id = server.id.clone();
    let req = AgentRequest::Connect {
        control_plane: app.cp_url.clone(),
        account: app.account.clone(),
        server: Some(id.clone()),
        exit: None,
        country: None,
        kill_switch: false,
    };
    match agent_request(&app.socket, &req).await {
        Ok(AgentResponse::Ok) => app.message = format!("connecting to {id}…"),
        Ok(AgentResponse::Error { message }) => app.message = format!("connect failed: {message}"),
        Ok(_) => {}
        Err(e) => app.message = format!("agent unreachable: {e} (is oxide-agentd running?)"),
    }
    refresh_status(app).await;
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
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(3),
    ])
    .areas(f.area());

    // --- header: title + live status ---
    let st = &app.status;
    let title = Line::from(Span::styled(
        "  Oxide VPN",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    let status_line = if st.connected {
        let flags = format!(
            "{}{}",
            if st.stealth { "stealth " } else { "" },
            if st.post_quantum { "PQ" } else { "" },
        );
        Line::from(vec![
            Span::styled(
                "  ● CONNECTED ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{}  up {}s  ↑{} ↓{}  {}",
                st.server_id.clone().unwrap_or_else(|| "?".into()),
                st.uptime_secs,
                human_bytes(st.tx_bytes),
                human_bytes(st.rx_bytes),
                flags,
            )),
        ])
    } else {
        Line::from(Span::styled(
            "  ○ disconnected",
            Style::default().fg(Color::DarkGray),
        ))
    };
    f.render_widget(
        Paragraph::new(vec![title, status_line]).block(Block::default().borders(Borders::BOTTOM)),
        header,
    );

    // --- body: server list ---
    let items: Vec<ListItem> = app
        .servers
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
            ListItem::new(format!(
                "{:<12} {:<16} load {:<9} {}",
                s.id, loc, load, health
            ))
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Servers "))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut list_state = ListState::default();
    if !app.servers.is_empty() {
        list_state.select(Some(app.selected));
    }
    f.render_stateful_widget(list, body, &mut list_state);

    // --- footer: keys + last message ---
    let help = "↑/↓ select · Enter connect · d disconnect · n new identity · r refresh · q quit";
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
