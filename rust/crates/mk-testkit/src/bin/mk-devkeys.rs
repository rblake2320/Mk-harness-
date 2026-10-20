//! Dev helper: prints an Ed25519 keypair (kid=k1) and a master key, and can
//! mint a 60-second actor assertion. Never used in production.
//!
//! mk-devkeys gen
//! mk-devkeys assert <private-key-b64url> <tenant-uuid> <user-uuid> <role,role>
use base64::Engine as _;
use mk_crypto::{ActorAssertion, AssertionSigner, MasterKey};

fn main() {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => {
            let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            println!(
                "MK_ASSERTION_KEYS=k1={}",
                b64.encode(key.verifying_key().to_bytes())
            );
            println!("DEV_PRIVATE_KEY={}", b64.encode(key.to_bytes()));
            println!(
                "MK_MASTER_KEY={}",
                base64::engine::general_purpose::STANDARD.encode(MasterKey::generate().as_bytes())
            );
        }
        Some("assert") => {
            let Some([sk, tenant, user, roles]) = args
                .get(2..6)
                .and_then(|s| <&[String; 4]>::try_from(s).ok())
            else {
                eprintln!("usage: mk-devkeys assert <sk> <tenant> <user> <roles>");
                std::process::exit(2);
            };
            let raw = b64.decode(sk).unwrap_or_default();
            let arr: [u8; 32] = raw.try_into().unwrap_or([0u8; 32]);
            let signer = AssertionSigner::new("k1", ed25519_dalek::SigningKey::from_bytes(&arr));
            let now = chrono::Utc::now().timestamp();
            let claims = ActorAssertion {
                iss: "mk-fastapi".into(),
                aud: "mk-action-kernel".into(),
                sub: tenant_or(user),
                tenant_id: tenant_or(tenant),
                roles: roles.split(',').map(str::to_owned).collect(),
                session_id: "dev".into(),
                request_id: uuid::Uuid::now_v7().to_string(),
                iat: now,
                exp: now + 60,
                jti: uuid::Uuid::now_v7(),
            };
            println!("{}", signer.sign(&claims).unwrap_or_default());
        }
        _ => eprintln!("usage: mk-devkeys gen | assert ..."),
    }
}

fn tenant_or(s: &str) -> uuid::Uuid {
    uuid::Uuid::parse_str(s).unwrap_or_default()
}
