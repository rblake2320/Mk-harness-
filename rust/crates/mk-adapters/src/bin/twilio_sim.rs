//! `mk-twilio-sim`: standalone Twilio Messages API simulator (test equipment).
//! Env: MK_TWSIM_ACCOUNT_SID, MK_TWSIM_AUTH_TOKEN, MK_TWSIM_MODE
//! (accept|opted_out|invalid|rate_limited|drop_response|error_then_accept),
//! MK_TWSIM_BIND (default 127.0.0.1:8790), MK_TWSIM_CALLBACK_BASE (where the
//! kernel actually listens; the signature is computed over the StatusCallback
//! URL the kernel supplied, exactly as Twilio does).
use mk_adapters::twilio_sim::{TwilioSimMode, TwilioSimulator};
use mk_crypto::AdapterSecret;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let account = std::env::var("MK_TWSIM_ACCOUNT_SID")?;
    let token = AdapterSecret::new(std::env::var("MK_TWSIM_AUTH_TOKEN")?);
    let mode = match std::env::var("MK_TWSIM_MODE")
        .unwrap_or_else(|_| "accept".into())
        .as_str()
    {
        "opted_out" => TwilioSimMode::RecipientOptedOut,
        "invalid" => TwilioSimMode::InvalidDestination,
        "rate_limited" => TwilioSimMode::RateLimited,
        "drop_response" => TwilioSimMode::AcceptButDropResponse,
        "error_then_accept" => TwilioSimMode::ServerErrorThenAccept(1),
        _ => TwilioSimMode::Accept,
    };
    let bind = std::env::var("MK_TWSIM_BIND").unwrap_or_else(|_| "127.0.0.1:8790".into());
    let callback_base = std::env::var("MK_TWSIM_CALLBACK_BASE").ok();
    let sim = TwilioSimulator::start_on(&bind, &account, token, mode).await?;
    eprintln!("mk-twilio-sim listening on {} (mode {mode:?})", sim.addr);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Some(base) = &callback_base {
            for m in sim.take_uncalled().await {
                for status in ["sent", "delivered"] {
                    match sim.post_status_for(&m, base, status).await {
                        Ok((code, _)) => eprintln!("callback {status} for {} → {code}", m["sid"]),
                        Err(e) => eprintln!("callback {status} failed: {e}"),
                    }
                }
            }
        }
    }
}
