//! Oxide VPN admin console (terminal UI).
//!
//! A read-only operator view over the control plane's admin API: fleet health, per-server
//! load and bandwidth, feature adoption, and an estimated running cost. Authenticates with the
//! control plane's admin bearer token (the same one that gates `provision`/`rotate-token`).
//!
//! It shows only fleet-level aggregates — never per-account data — so operating the fleet
//! doesn't mean watching users.

mod app;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Parser;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use futures::StreamExt;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Tabs};
use ratatui::{DefaultTerminal, Frame};

use app::{
    adoption, hours_since, human_bytes, load_fraction, server_alert, Alert, App, CostModel, Tab,
};
use oxide_common::api::AdminServerInfo;
use oxide_control_client::ControlClient;

#[derive(Parser)]
#[command(name = "oxide-admin-tui", about = "Oxide VPN admin console")]
struct Cli {
    /// Control-plane base URL, e.g. http://127.0.0.1:8080.
    #[arg(long)]
    control_plane: String,
    /// Admin bearer token (the control plane's `--admin-token`). Also read from
    /// OXIDE_ADMIN_TOKEN so it needn't appear in shell history.
    #[arg(long, env = "OXIDE_ADMIN_TOKEN")]
    admin_token: String,
    /// Estimated egress bandwidth price, USD per GB (10^9 bytes).
    #[arg(long, default_value_t = 0.09)]
    cost_per_gb: f64,
    /// Estimated server price, USD per running server-hour.
    #[arg(long, default_value_t = 0.02)]
    cost_per_server_hour: f64,
    /// Seconds between auto-refreshes.
    #[arg(long, default_value_t = 3)]
    refresh_secs: u64,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cost = CostModel {
        per_gb: cli.cost_per_gb,
        per_server_hour: cli.cost_per_server_hour,
    };
    let mut app = App::new(cli.control_plane, cli.admin_token, cost);
    refresh(&mut app).await;

    let mut terminal = ratatui::init();
    let res = run(&mut terminal, &mut app, cli.refresh_secs.max(1)).await;
    ratatui::restore();
    res
}

async fn run(terminal: &mut DefaultTerminal, app: &mut App, refresh_secs: u64) -> Result<()> {
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_secs(refresh_secs));
    loop {
        terminal.draw(|f| draw(f, app))?;
        tokio::select! {
            _ = tick.tick() => refresh(app).await,
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
    // A rotate-token confirmation is armed: only y/n (or Enter/Esc) answer it.
    if app.confirm_rotate.is_some() {
        match code {
            KeyCode::Char('y') | KeyCode::Enter => rotate_selected_token(app).await,
            _ => {
                app.confirm_rotate = None;
                app.message = "rotation cancelled".into();
            }
        }
        return;
    }
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('r') => refresh(app).await,
        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => app.tab = app.tab.next(),
        KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => app.tab = app.tab.prev(),
        KeyCode::Char('1') => app.tab = Tab::Overview,
        KeyCode::Char('2') => app.tab = Tab::Servers,
        KeyCode::Char('3') => app.tab = Tab::Features,
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
        // Arm token rotation for the selected server (Servers tab only) — confirmed with y.
        KeyCode::Char('R') if app.tab == Tab::Servers => {
            if let Some(id) = app.selected_server().map(|s| s.id.clone()) {
                app.message = format!("rotate {id}'s token? y to confirm, any key to cancel");
                app.confirm_rotate = Some(id);
            }
        }
        _ => {}
    }
}

/// Rotate the armed server's auth token via the admin API and surface the new token so the
/// operator can update the server's config (the old token stays valid during the grace window).
async fn rotate_selected_token(app: &mut App) {
    let Some(id) = app.confirm_rotate.take() else {
        return;
    };
    let cc = ControlClient::new(&app.cp_url);
    match cc.admin_rotate_token(&app.admin_token, &id).await {
        Ok(resp) => {
            app.message = format!(
                "{id}: new token {} (previous valid {}s) — update the server config",
                resp.auth_token, resp.previous_valid_secs
            );
        }
        Err(e) => app.message = format!("rotate failed for {id}: {e}"),
    }
}

/// Pull the overview + server list from the control plane's admin API.
async fn refresh(app: &mut App) {
    let cc = ControlClient::new(&app.cp_url);
    match cc.admin_overview(&app.admin_token).await {
        Ok(o) => app.overview = Some(o),
        Err(e) => {
            app.message = format!("admin API error: {e} (token? --control-plane?)");
            return;
        }
    }
    match cc.admin_list_servers(&app.admin_token).await {
        Ok(s) => {
            app.set_servers(s);
            app.now = now_unix();
            app.message = format!("{} servers · refreshed", app.servers.len());
        }
        Err(e) => app.message = format!("server list error: {e}"),
    }
}

fn draw(f: &mut Frame, app: &App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .areas(f.area());

    draw_header(f, app, header);
    match app.tab {
        Tab::Overview => draw_overview(f, app, body),
        Tab::Servers => draw_servers(f, app, body),
        Tab::Features => draw_features(f, app, body),
    }
    draw_footer(f, app, footer);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let [title_area, tabs_area, alert_area] = Layout::horizontal([
        Constraint::Length(18),
        Constraint::Min(0),
        Constraint::Length(16),
    ])
    .areas(area);

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "  Oxide Admin",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )))
        .block(Block::default().borders(Borders::BOTTOM)),
        title_area,
    );

    let titles = Tab::ALL.iter().map(|t| t.title());
    f.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(" ")
            .block(Block::default().borders(Borders::BOTTOM)),
        tabs_area,
    );

    // Right-aligned fleet alert chip, always visible regardless of tab.
    let alerts = app.alert_count();
    let chip = if alerts > 0 {
        Span::styled(
            format!("⚠ {alerts} alert{} ", if alerts == 1 { "" } else { "s" }),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("✓ all healthy ", Style::default().fg(Color::Green))
    };
    f.render_widget(
        Paragraph::new(Line::from(chip))
            .alignment(Alignment::Right)
            .block(Block::default().borders(Borders::BOTTOM)),
        alert_area,
    );
}

/// Big-number stat cards for the fleet.
fn draw_overview(f: &mut Frame, app: &App, area: Rect) {
    let Some(o) = &app.overview else {
        f.render_widget(Paragraph::new("  no data yet"), area);
        return;
    };

    let health = format!("{}/{}", o.healthy_servers, o.servers);
    let health_color = if o.servers > 0 && o.healthy_servers == o.servers {
        Color::Green
    } else if o.healthy_servers == 0 {
        Color::Red
    } else {
        Color::Yellow
    };
    let bandwidth = format!(
        "↑{} ↓{}",
        human_bytes(o.tx_bytes_total),
        human_bytes(o.rx_bytes_total)
    );
    let cost = format!("${:.2}", app.fleet_cost());

    let cards: [(&str, String, Color); 6] = [
        ("Servers healthy", health, health_color),
        ("Active peers", o.active_peers.to_string(), Color::Cyan),
        ("Accounts", o.accounts.to_string(), Color::Cyan),
        ("Devices", o.devices.to_string(), Color::Cyan),
        ("Bandwidth (tx/rx)", bandwidth, Color::Blue),
        ("Est. cost", cost, Color::Green),
    ];

    // Two rows of three cards.
    let rows = Layout::vertical([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).split(area);
    for (r, row) in rows.iter().enumerate() {
        let cols = Layout::horizontal([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(*row);
        for (c, col) in cols.iter().enumerate() {
            let (label, value, color) = &cards[r * 3 + c];
            let card = Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    value.clone(),
                    Style::default().fg(*color).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    label.to_string(),
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(card, *col);
        }
    }
}

/// Servers tab: the fleet list on the left, a detail pane for the selected server on the right.
fn draw_servers(f: &mut Frame, app: &App, area: Rect) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Min(40), Constraint::Length(38)]).areas(area);

    let items: Vec<ListItem> = app.servers.iter().map(|s| server_row(app, s)).collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Servers — ⚠ alert · id · location · load · features · health · $ "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    if !app.servers.is_empty() {
        state.select(Some(app.selected));
    }
    f.render_stateful_widget(list, list_area, &mut state);
    draw_server_detail(f, app, detail_area);
}

fn server_row<'a>(app: &App, s: &'a AdminServerInfo) -> ListItem<'a> {
    let loc = match (&s.country, &s.city) {
        (Some(c), Some(city)) => format!("{c}/{city}"),
        (Some(c), None) => c.clone(),
        _ => "-".into(),
    };
    let load = match load_fraction(s.active_peers, s.capacity) {
        Some(frac) => format!("{}/{} {}", s.active_peers, s.capacity, bar(frac, 8)),
        None => format!("{} peers", s.active_peers),
    };
    let health = if s.healthy {
        Span::styled("● up", Style::default().fg(Color::Green))
    } else {
        Span::styled("× stale", Style::default().fg(Color::Red))
    };
    // Leading alert marker so a stale/overloaded server jumps out of the list.
    let alert = match server_alert(s) {
        Some(Alert::Stale) => Span::styled("⚠ ", Style::default().fg(Color::Red)),
        Some(Alert::HighLoad) => Span::styled("⚠ ", Style::default().fg(Color::Yellow)),
        None => Span::raw("  "),
    };

    let mut spans = vec![
        alert,
        Span::styled(
            format!("{:<12}", s.id),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{loc:<12} ")),
        Span::raw(format!("{load:<20} ")),
    ];
    spans.extend(feature_badges(s));
    spans.push(Span::raw("  "));
    spans.push(health);
    spans.push(Span::styled(
        format!("  ${:.2}", app.server_cost(s)),
        Style::default().fg(Color::Green),
    ));
    ListItem::new(Line::from(spans))
}

/// Detail pane for the selected server: full metadata, an alert banner, bandwidth, and cost.
fn draw_server_detail(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Detail ");
    let Some(s) = app.selected_server() else {
        f.render_widget(Paragraph::new("  no server selected").block(block), area);
        return;
    };

    let kv = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("  {k:<11}"), Style::default().fg(Color::DarkGray)),
            Span::raw(v),
        ])
    };
    let loc = match (&s.country, &s.city) {
        (Some(c), Some(city)) => format!("{c} / {city}"),
        (Some(c), None) => c.clone(),
        _ => "—".into(),
    };
    let heartbeat = match s.last_heartbeat_secs {
        Some(a) => format!("{a}s ago"),
        None => "never".into(),
    };
    let transport = s.transport.as_deref().unwrap_or("plain");
    let features = {
        let mut f = vec![transport.to_string()];
        if s.daita {
            f.push("daita".into());
        }
        if s.post_quantum {
            f.push("pq".into());
        }
        if s.stealth {
            f.push("stealth".into());
        }
        f.join(" · ")
    };

    let mut lines = vec![
        Line::from(Span::styled(
            format!("  {}", s.id),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    // Alert banner, if any.
    if let Some(alert) = server_alert(s) {
        let color = if alert == Alert::Stale {
            Color::Red
        } else {
            Color::Yellow
        };
        lines.push(Line::from(Span::styled(
            format!("  ⚠ {}", alert.label()),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }
    lines.push(kv("endpoint", s.endpoint.clone()));
    lines.push(kv("location", loc));
    lines.push(kv(
        "load",
        match load_fraction(s.active_peers, s.capacity) {
            Some(frac) => format!("{}/{} ({:.0}%)", s.active_peers, s.capacity, frac * 100.0),
            None => format!("{} peers (uncapped)", s.active_peers),
        },
    ));
    lines.push(kv("features", features));
    lines.push(kv(
        "bandwidth",
        format!(
            "↑{} ↓{}",
            human_bytes(s.tx_bytes_total),
            human_bytes(s.rx_bytes_total)
        ),
    ));
    lines.push(kv("heartbeat", heartbeat));
    lines.push(kv(
        "uptime",
        format!("{:.1}h", hours_since(s.created_at, app.now)),
    ));
    lines.push(kv("est. cost", format!("${:.2}", app.server_cost(s))));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  R rotate token",
        Style::default().fg(Color::DarkGray),
    )));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Colored one-letter badges for the transport/privacy features a server runs.
fn feature_badges(s: &AdminServerInfo) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let transport = s.transport.as_deref().unwrap_or("plain");
    let (t_label, t_color) = match transport {
        "quic" => ("QUIC", Color::Cyan),
        "mimic" => ("MIMIC", Color::Cyan),
        "obfs" => ("OBFS", Color::Blue),
        _ => ("PLAIN", Color::DarkGray),
    };
    out.push(Span::styled(
        format!("[{t_label}]"),
        Style::default().fg(t_color),
    ));
    if s.daita {
        out.push(Span::styled(
            " [DAITA]",
            Style::default().fg(Color::Magenta),
        ));
    }
    if s.post_quantum {
        out.push(Span::styled(" [PQ]", Style::default().fg(Color::Yellow)));
    }
    if s.stealth {
        out.push(Span::styled(" [STL]", Style::default().fg(Color::Green)));
    }
    out
}

/// Fleet-wide feature adoption as labeled gauges.
fn draw_features(f: &mut Frame, app: &App, area: Rect) {
    let Some(o) = &app.overview else {
        f.render_widget(Paragraph::new("  no data yet"), area);
        return;
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Feature adoption across the fleet ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = [
        ("Stealth transport", o.stealth_servers, Color::Green),
        ("QUIC mimicry", o.quic_servers, Color::Cyan),
        ("DAITA defense", o.daita_servers, Color::Magenta),
        ("Post-quantum", o.pq_servers, Color::Yellow),
    ];
    let chunks = Layout::vertical([Constraint::Length(2); 4]).split(inner);
    for ((label, count, color), chunk) in rows.iter().zip(chunks.iter()) {
        let frac = adoption(*count, o.servers);
        let g = Gauge::default()
            .block(Block::default().title(format!("{label}  ({count}/{})", o.servers)))
            .gauge_style(Style::default().fg(*color))
            .ratio(frac)
            .label(format!("{:.0}%", frac * 100.0));
        f.render_widget(g, *chunk);
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    // A destructive-action confirmation takes over the help line in bold yellow.
    let help_line = if let Some(id) = &app.confirm_rotate {
        Line::from(Span::styled(
            format!("  rotate {id}'s token? y = confirm · any other key = cancel"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(Span::styled(
            "  1/2/3 or ←/→ tabs · ↑/↓ select · R rotate-token · r refresh · q quit",
            Style::default().fg(Color::DarkGray),
        ))
    };
    f.render_widget(
        Paragraph::new(vec![
            help_line,
            Line::from(Span::raw(format!("  {}", app.message))),
        ]),
        area,
    );
}

/// A tiny text progress bar like `████░░░░` for a 0..1 fraction.
fn bar(frac: f64, width: usize) -> String {
    let frac = frac.clamp(0.0, 1.0);
    let filled = (frac * width as f64).round() as usize;
    let mut s = String::with_capacity(width);
    for i in 0..width {
        s.push(if i < filled { '█' } else { '░' });
    }
    s
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use oxide_common::api::{AdminOverview, AdminServerInfo};
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

    fn seeded_app() -> App {
        let mut app = App::new(
            "http://cp".into(),
            "tok".into(),
            CostModel {
                per_gb: 0.09,
                per_server_hour: 0.02,
            },
        );
        app.now = 7200;
        app.overview = Some(AdminOverview {
            accounts: 12,
            servers: 2,
            devices: 20,
            healthy_servers: 2,
            active_peers: 15,
            tx_bytes_total: 3_000_000_000,
            rx_bytes_total: 1_500_000_000,
            stealth_servers: 1,
            quic_servers: 1,
            daita_servers: 1,
            pq_servers: 2,
        });
        app.set_servers(vec![
            AdminServerInfo {
                id: "us-a".into(),
                endpoint: "203.0.113.9:51820".into(),
                country: Some("US".into()),
                city: Some("NYC".into()),
                capacity: 100,
                active_peers: 40,
                healthy: true,
                transport: Some("quic".into()),
                daita: true,
                post_quantum: true,
                stealth: false,
                tx_bytes_total: 2_000_000_000,
                rx_bytes_total: 1_000_000_000,
                last_heartbeat_secs: Some(3),
                created_at: 0,
            },
            AdminServerInfo {
                id: "de-b".into(),
                endpoint: "198.51.100.4:51820".into(),
                country: Some("DE".into()),
                city: None,
                capacity: 0,
                active_peers: 5,
                healthy: false,
                transport: None,
                daita: false,
                post_quantum: true,
                stealth: true,
                tx_bytes_total: 1_000_000_000,
                rx_bytes_total: 500_000_000,
                last_heartbeat_secs: Some(200),
                created_at: 0,
            },
        ]);
        app
    }

    /// Every tab renders one frame without panicking, and surfaces the data it should.
    #[test]
    fn all_tabs_render() {
        for tab in Tab::ALL {
            let mut app = seeded_app();
            app.tab = tab;
            let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
            terminal.draw(|f| draw(f, &app)).unwrap();
            let text = buffer_text(&terminal);
            assert!(text.contains("Oxide Admin"), "title on {tab:?}");
        }
    }

    #[test]
    fn overview_shows_cost_and_health() {
        let mut app = seeded_app();
        app.tab = Tab::Overview;
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("2/2"), "healthy count"); // all healthy
        assert!(text.contains('$'), "cost card"); // estimated cost rendered
    }

    #[test]
    fn servers_tab_shows_ids_and_badges() {
        let mut app = seeded_app();
        app.tab = Tab::Servers;
        let mut terminal = Terminal::new(TestBackend::new(140, 24)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("us-a"));
        assert!(text.contains("QUIC"));
        assert!(text.contains("DAITA"));
    }

    #[test]
    fn alert_chip_and_detail_pane_render() {
        // seeded_app has one stale server (de-b, healthy:false), so an alert chip shows.
        let mut app = seeded_app();
        app.tab = Tab::Servers;
        app.selected = 0; // us-a → detail pane shows its metadata
        let mut terminal = Terminal::new(TestBackend::new(140, 24)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("1 alert"), "header alert chip");
        assert!(text.contains("Detail"), "detail pane title");
        assert!(text.contains("endpoint"), "detail shows metadata");
        assert!(
            text.contains("rotate token"),
            "detail shows the rotate hint"
        );
    }

    #[test]
    fn rotate_confirm_prompt_shows_in_footer() {
        let mut app = seeded_app();
        app.tab = Tab::Servers;
        app.confirm_rotate = Some("us-a".into());
        let mut terminal = Terminal::new(TestBackend::new(140, 24)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let text = buffer_text(&terminal);
        assert!(
            text.contains("y = confirm"),
            "confirmation prompt in footer"
        );
    }
}
