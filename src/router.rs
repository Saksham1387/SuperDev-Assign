use axum::{routing::{get, post}, Router};
use crate::handler::{generate_keypair_handler, create_token_handler, mint_token_handler,sign_message_handler, verify_message_handler, send_sol_handler, transfer_token_handler};

pub fn router( ) -> Router {
    Router::new()
        .route("/keypair", post(generate_keypair_handler))
        .route("/token/create", post(create_token_handler))
        .route("/token/mint", post(mint_token_handler))
        .route("/message/sign", post(sign_message_handler))
        .route("/message/verify", post(verify_message_handler))
        .route("/send/sol", post(send_sol_handler))
        .route("/send/token", post(transfer_token_handler))
}