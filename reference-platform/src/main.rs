//! `ptpan-reference-platform`: serve `PlatformService` and the ingress socket,
//! or run one user or owner action against the platform's own record.

use ptpan_reference_platform::{ApprovalTerms, Config, Platform};
use std::sync::Arc;

const USAGE: &str = "usage: ptpan-reference-platform <config.json> <command>
  serve
  account add <account> <given-name> <family-name>
  agent add <agent> <account>                 prints the agent's address
  address retire <address>
  request create <account> <agent> <address> <perm,perm> <FIXED|SINGLE_TASK|UNTIL_REVOKED> <seconds>
  request state <request-id>
  request relationship <request-id>
  inbox list
  inbox approve <account> <source-platform> <request-id> <perm,perm> <mode> <seconds>
  inbox deny|block <account> <source-platform> <request-id>
  relationship ready|revoke <relationship-id>
  block set|clear <source-platform> <requester-reference> <address>
  call <relationship-id> <text>
  hold <relationship-id> <max-seconds>";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args).await {
        eprintln!("{e}\n{USAGE}");
        std::process::exit(2);
    }
}

fn terms(perms: &str, mode: &str, seconds: &str) -> Result<ApprovalTerms, ptpan_reference_platform::Error> {
    Ok(ApprovalTerms {
        permissions: perms.split(',').map(str::to_owned).collect(),
        mode: mode.into(),
        lifetime_seconds: seconds.parse()?,
    })
}

async fn run(args: &[String]) -> Result<(), ptpan_reference_platform::Error> {
    let arg = |i: usize| args.get(i).map(String::as_str).ok_or("missing argument");
    let config: Config = serde_json::from_slice(&std::fs::read(arg(0)?)?)?;
    let platform = Arc::new(Platform::open(config)?);
    let wake = |p: Arc<Platform>| async move {
        if let Ok(mut client) = p.adapter_client().await {
            let _ = client.wake(ptpan_platform_api::v1::WakeRequest {}).await;
        }
    };
    match (arg(1)?, args.get(2).map(String::as_str)) {
        ("serve", _) => platform.serve().await,
        ("account", Some("add")) => platform.add_account(arg(3)?, arg(4)?, arg(5)?),
        ("agent", Some("add")) => {
            println!("{}", platform.add_agent(arg(3)?, arg(4)?)?);
            Ok(())
        },
        ("address", Some("retire")) => platform.retire_address(arg(3)?),
        ("request", Some("create")) => {
            let id = platform.create_request(arg(3)?, arg(4)?, arg(5)?, &terms(arg(6)?, arg(7)?, arg(8)?)?)?;
            wake(platform.clone()).await;
            {
            println!("{id}");
            Ok(())
        }
        }
        ("request", Some("state")) => {
            println!("{}", platform.sent_state(arg(3)?)?.unwrap_or_default());
            Ok(())
        },
        ("request", Some("relationship")) => {
            println!("{}", platform.relationship_of(arg(3)?)?.unwrap_or_default());
            Ok(())
        },
        ("inbox", Some("list")) => {
            println!("{}", serde_json::to_string_pretty(&platform.inbox()?)?);
            Ok(())
        },
        ("inbox", Some("approve")) => {
            platform.approve(arg(3)?, arg(4)?, arg(5)?, &terms(arg(6)?, arg(7)?, arg(8)?)?)?;
            let _ = platform.complete_intents().await;
            wake(platform.clone()).await;
            Ok(())
        }
        ("inbox", Some(action @ ("deny" | "block"))) => {
            platform.deny(arg(3)?, arg(4)?, arg(5)?, action == "block")?;
            wake(platform.clone()).await;
            Ok(())
        }
        ("relationship", Some("ready")) => {
            println!("{}", platform.is_ready(arg(3)?)?);
            Ok(())
        },
        ("relationship", Some("revoke")) => {
            platform.revoke(arg(3)?, "OWNER_REVOKED")?;
            wake(platform.clone()).await;
            Ok(())
        }
        ("block", Some(action @ ("set" | "clear"))) => {
            platform.set_block(arg(3)?, arg(4)?, arg(5)?, action == "set")?;
            wake(platform.clone()).await;
            Ok(())
        }
        ("call", _) => {
            let (response, echoed) = platform.call_agent(arg(2)?, arg(3)?.as_bytes()).await?;
            println!("{}", serde_json::json!({"response": response, "echo": String::from_utf8_lossy(&echoed)}));
            Ok(())
        }
        ("hold", _) => {
            let (response, held) = platform.hold_agent(arg(2)?, arg(3)?.parse()?).await?;
            println!("{}", serde_json::json!({"response": response, "held_seconds": held}));
            Ok(())
        }
        _ => Err("unknown command".into()),
    }
}
