pub mod zkp_auth {
    include!("../../zkp_auth.rs");
}

pub mod grpc_impl;

use anyhow::anyhow;
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().map_err(|err| anyhow!("Err: {err}"))?;
    env_logger::try_init().map_err(|err| anyhow!("Err: {err}"))?;

    let addr = "127.0.0.1:5051".to_string();
    log::info!("Server running at {addr}");

    let auth_impl = grpc_impl::auth::auth_impl::AuthImpl::default();

    tonic::transport::Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("Could not convert address"))
        .await
        .unwrap();

    Ok(())
}
