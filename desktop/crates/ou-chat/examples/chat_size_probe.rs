//! Links the whole chat stack into one binary so its release size can be measured (`cargo build --release --example
//! chat_size_probe`). Restores a session if one exists in an empty in-memory store (it never does) and exits.
use std::sync::Arc;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let account = ou_chat::ChatAccount {
        account_id: "probe".into(),
        homeserver: url::Url::parse("https://matrix.example.invalid/").unwrap(),
        client_uri: url::Url::parse("https://app.example.invalid/").unwrap(),
        data_dir: std::env::temp_dir().join("ou-chat-probe"),
    };
    let store: Arc<dyn ou_core::secrets::SecretStore> = Arc::new(ou_core::secrets::MemoryStore::new());
    let r = ou_chat::ChatClient::restore(account, ou_core::http::client().unwrap(), store).await;
    println!("restored: {}", matches!(r, Ok(Some(_))));
}
