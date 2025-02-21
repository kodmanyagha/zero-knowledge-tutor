use anyhow::anyhow;
use zkp_auth::auth_client::AuthClient;

pub mod zkp_auth {
    include!("../../zkp_auth.rs");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().map_err(|err| anyhow!("Err: {err}"))?;
    env_logger::try_init().map_err(|err| anyhow!("Err: {err}"))?;

    let client = AuthClient::connect("http://127.0.0.1:5051")
        .await
        .expect("Can't connect to the server.");

    log::info!("Connected to the server.");

    Ok(())
}
