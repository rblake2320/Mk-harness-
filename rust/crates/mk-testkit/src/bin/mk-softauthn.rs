//! Software WebAuthn authenticator — TEST EQUIPMENT for the live smoke and
//! browser-less acceptance runs. Produces the exact byte formats a platform
//! authenticator does so the kernel's verifier is exercised end to end.
//! Never part of a production image; the key state file is plaintext.
//!
//! mk-softauthn new <state-file> [es256|ed25519]
//! mk-softauthn register <state-file> <challenge-b64url> <rp-id> <origin>
//!     → JSON {client_data_json, attestation_object}
//! mk-softauthn assert <state-file> <challenge-b64url> <rp-id> <origin>
//!     → JSON {credential_id, client_data_json, authenticator_data, signature}
use mk_crypto::webauthn::softauthn::SoftAuthenticator;
use mk_crypto::webauthn::{b64url, b64url_decode};

fn usage() -> ! {
    eprintln!(
        "usage: mk-softauthn new <state> [es256|ed25519] | register <state> <challenge> <rp> <origin> | assert <state> <challenge> <rp> <origin>"
    );
    std::process::exit(2)
}

fn load(path: &str) -> SoftAuthenticator {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("state file: {e}");
        std::process::exit(2)
    });
    SoftAuthenticator::import(&s).unwrap_or_else(|e| {
        eprintln!("state file: {e}");
        std::process::exit(2)
    })
}

fn save(path: &str, a: &SoftAuthenticator) {
    if let Err(e) = std::fs::write(path, a.export()) {
        eprintln!("state file: {e}");
        std::process::exit(2)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("new") => {
            let Some(path) = args.get(2) else { usage() };
            let a = match args.get(3).map(String::as_str) {
                Some("ed25519") => SoftAuthenticator::new_ed25519(),
                _ => SoftAuthenticator::new_es256(),
            };
            save(path, &a);
            println!("{}", b64url(&a.credential_id));
        }
        Some(cmd @ ("register" | "assert")) => {
            let Some([path, challenge, rp, origin]) = args
                .get(2..6)
                .and_then(|s| <&[String; 4]>::try_from(s).ok())
            else {
                usage()
            };
            let challenge = b64url_decode(challenge).unwrap_or_else(|e| {
                eprintln!("challenge: {e}");
                std::process::exit(2)
            });
            let mut a = load(path);
            let out = if cmd == "register" {
                let (cdj, att) = a.register(&challenge, rp, origin);
                serde_json::json!({"client_data_json": b64url(&cdj), "attestation_object": b64url(&att), "label": "softauthn"})
            } else {
                let (cdj, ad, sig) = a.assert(&challenge, rp, origin);
                serde_json::json!({"credential_id": b64url(&a.credential_id), "client_data_json": b64url(&cdj),
                                   "authenticator_data": b64url(&ad), "signature": b64url(&sig)})
            };
            save(path, &a);
            println!("{out}");
        }
        _ => usage(),
    }
}
