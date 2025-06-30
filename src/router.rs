use axum::{routing::get, Router};
use crate::handler::get_balance_handler;

use super::handler::hello_world_handler;

pub fn router( ) -> Router {
    Router::new()
        .route("/", get(hello_world_handler))
        .route("/balance", get(get_balance_handler))
}