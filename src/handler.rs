use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, pubkey};
use serde_json::json;
use axum::{response::IntoResponse, Json};

pub async fn hello_world_handler() -> &'static str {
    "Hello World"
}

pub async fn get_balance_handler() -> impl IntoResponse {
    let client = RpcClient::new_with_commitment(
        String::from("https://api.mainnet-beta.solana.com"),
        CommitmentConfig::confirmed(),
    );

    let address = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    let balance = client.get_balance(&address).await;
    
   match balance {
        Ok(balance) => Json(json!({
            "balance": balance as f64 / LAMPORTS_PER_SOL as f64
        })),
        Err(err) => {
            println!("Error: {}", err);
            Json(json!({
                "balance": 0.0
            }))
        }
    }
}