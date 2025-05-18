use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use tokio::fs;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);
    let state = HttpServeState { path: path.clone() };
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, String) {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            format!("File {} not found", p.display()),
        )
    } else {
        let content = if p.is_dir() {
            let mut files = Vec::new();
            match fs::read_dir(p).await {
                Ok(mut dir) => {
                    while let Ok(Some(entry)) = dir.next_entry().await {
                        let path = entry.path();
                        let file_name = entry.file_name().to_string_lossy().to_string();
                        let link = path.display();
                        files.push(format!("<li><a href=\"{}\">{}</a></li>", link, file_name));
                    }
                }
                Err(e) => {
                    warn!("Failed to read directory: {:?}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
                }
            }
            format!("<html><body><ul>{}</ul></body></html>", files.join("\n"))
        } else {
            match tokio::fs::read_to_string(p).await {
                Ok(content) => content,
                Err(e) => {
                    warn!("Failed to read file: {:?}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
                }
            }
        };
        (StatusCode::OK, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, content) = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content.trim().starts_with("[package]"))
    }
}
