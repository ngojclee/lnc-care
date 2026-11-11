//! LNC Care binary entrypoint (`serve`, `worker`, `healthcheck`, `rotate-vault`).

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

use lnc_care::routes::{build_router, AppConfig};
use lnc_care::transport::{HttpTransport, TransportRequest, UreqTransport};
use lnc_care::vault::Vault;
use lnc_care::{audit, store, worker};

fn resolve_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("DATABASE_PATH") {
        if !p.trim().is_empty() {
            return PathBuf::from(p.trim());
        }
    }
    if let Ok(dd) = std::env::var("DATA_DIR") {
        if !dd.trim().is_empty() {
            return PathBuf::from(dd.trim()).join("care.db");
        }
    }
    PathBuf::from("data").join("lnc-care.db")
}

fn resolve_org() -> (String, String) {
    let org = std::env::var("ORGANIZATION_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("DEFAULT_ORG_SLUG")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "lnc-default".to_string());
    let name = std::env::var("ORGANIZATION_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("DEFAULT_ORG_NAME")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "Le Ngoc Care".to_string());
    (org, name)
}

fn resolve_port() -> u16 {
    std::env::var("PORT_INTERNAL")
        .or_else(|_| std::env::var("PORT"))
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(8000)
}

fn run_healthcheck() -> i32 {
    let port = resolve_port();
    let url = format!("http://127.0.0.1:{port}/health");
    let client = UreqTransport;
    match client.execute(TransportRequest {
        method: "GET".to_string(),
        url,
        headers: Vec::new(),
        body: None,
        timeout_ms: 4_000,
    }) {
        Ok(res) if res.status == 200 => {
            if let Ok(val) = res.json() {
                if val.get("status").and_then(|v| v.as_str()) == Some("ok") {
                    return 0;
                }
            }
            1
        }
        _ => 1,
    }
}

fn run_rotate_vault(args: &[String]) -> Result<(), String> {
    let mut new_key_arg: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--new-key" && i + 1 < args.len() {
            new_key_arg = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }

    let path = resolve_db_path();
    let (org, org_name) = resolve_org();
    store::initialize(&path, &org, &org_name).map_err(|e| e.to_string())?;

    let prev_env = std::env::var("LNC_PREVIOUS_MASTER_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let cur_env = std::env::var("LNC_MASTER_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let (old_key, new_key) = if let Some(nk) = new_key_arg.or_else(|| {
        std::env::var("LNC_NEW_MASTER_KEY")
            .ok()
            .filter(|s| !s.trim().is_empty())
    }) {
        let ok = cur_env.ok_or_else(|| "LNC_MASTER_KEY is required".to_string())?;
        (ok, nk)
    } else if let (Some(pk), Some(ck)) = (prev_env, cur_env) {
        (pk, ck)
    } else {
        return Err(
            "Provide --new-key / LNC_NEW_MASTER_KEY (with LNC_MASTER_KEY) or set both LNC_PREVIOUS_MASTER_KEY and LNC_MASTER_KEY"
                .to_string(),
        );
    };

    let vault = Vault::new(Some(&old_key), None).map_err(|e| e.0)?;
    let count = store::with_write_tx_str(&path, |db| -> Result<usize, String> {
        let n = vault.rewrap(db, &org, &new_key).map_err(|e| e.0)?;
        audit::append(
            db,
            &org,
            "cli",
            "vault.rotated",
            "secret_envelopes",
            &json!({ "rewrapped": n }),
        )
        .map_err(|e| e.to_string())?;
        Ok(n)
    })?;

    println!("{}", json!({ "ok": true, "rewrapped": count }));
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("serve");

    match cmd {
        "healthcheck" => {
            std::process::exit(run_healthcheck());
        }
        "rotate-vault" => {
            if let Err(err) = run_rotate_vault(&args[1..]) {
                eprintln!("rotate-vault failed: {err}");
                std::process::exit(1);
            }
        }
        "worker" => {
            let path = resolve_db_path();
            let (org, org_name) = resolve_org();
            if let Err(e) = store::initialize(&path, &org, &org_name) {
                eprintln!("worker db init failed: {e}");
                std::process::exit(1);
            }
            eprintln!("lnc-care worker v{} started (db={})", lnc_care::VERSION, path.display());
            loop {
                let _ = worker::run_pending_jobs(&path, &org, 10, "lnc-care-worker");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        "serve" | _ => {
            let port = resolve_port();
            let app = match build_router(AppConfig::default()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("failed to initialize lnc-care router: {e}");
                    std::process::exit(1);
                }
            };
            let addr = format!("0.0.0.0:{port}");
            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("failed to bind {addr}: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("lnc-care v{} listening on http://{addr}", lnc_care::VERSION);
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("server error: {e}");
                std::process::exit(1);
            }
        }
    }
}
