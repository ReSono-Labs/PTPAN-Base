//! `ptpan-adapter` command line: run the adapter, or apply one operator
//! action to the peer store. A running adapter picks operator changes up
//! without a restart (principle 10).

use federation_base::identity_evidence::BootstrapAuthority;
use federation_base::time::{now_unix, utc_unix_seconds};
use federation_base::PlatformId;
use ptpan_adapter::config::Config;
use ptpan_adapter::Adapter;
use std::path::Path;

const USAGE: &str = "usage:
  ptpan-adapter run <config.json>
  ptpan-adapter peer add <config.json> <bootstrap.json>
  ptpan-adapter peer approve|approve-pending|suspend|resume|remove <config.json> <platform-id>
  ptpan-adapter manifest propose <config.json> <manifest.json> <effective-at RFC3339 UTC>
  ptpan-adapter status <config.json>";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args).await {
        eprintln!("{e}\n{USAGE}");
        std::process::exit(2);
    }
}

async fn adapter(config: &str) -> Result<std::sync::Arc<Adapter>, ptpan_adapter::Error> {
    Adapter::new(Config::load(Path::new(config))?).await
}

async fn run(args: &[String]) -> Result<(), ptpan_adapter::Error> {
    let arg = |i: usize| args.get(i).map(String::as_str).ok_or("missing argument");
    let now = now_unix();
    match (arg(0)?, args.get(1).map(String::as_str)) {
        ("run", _) => adapter(arg(1)?).await?.run().await,
        ("peer", Some("add")) => {
            let bootstrap: BootstrapAuthority = serde_json::from_slice(&std::fs::read(arg(3)?)?)?;
            adapter(arg(2)?).await?.add_peer(bootstrap, now).await
        }
        ("peer", Some(action)) => {
            let a = adapter(arg(2)?).await?;
            let peer = PlatformId::new(arg(3)?)?;
            match action {
                "approve" => a.approve_peer(&peer, now).await,
                "approve-pending" => a.approve_pending(&peer, now).await,
                "suspend" => a.suspend_peer(&peer, now).await,
                "resume" => a.resume_peer(&peer, now).await,
                "remove" => a.remove_peer(&peer, now).await,
                _ => Err("unknown peer action".into()),
            }
        }
        ("manifest", Some("propose")) => {
            let bytes = std::fs::read(arg(3)?)?;
            let effective_at = utc_unix_seconds(arg(4)?).ok_or("effective-at must be RFC 3339 UTC")? as u64;
            adapter(arg(2)?).await?.propose_manifest(&bytes, effective_at, now).await
        }
        ("status", _) => {
            let a = adapter(arg(1)?).await?;
            let peers: Vec<serde_json::Value> = a
                .peer_states(now)
                .await?
                .into_iter()
                .map(|(id, state, queued)| serde_json::json!({"peer": id, "state": format!("{state:?}"), "queued": queued}))
                .collect();
            println!("{}", serde_json::to_string_pretty(&peers)?);
            Ok(())
        }
        _ => Err("unknown command".into()),
    }
}
