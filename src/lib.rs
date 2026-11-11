//! LNC Care (`v0.5.0.0`) — Owned social care, AI rubric triage, forensic Evidence Vault, Multi-Account Fleet & MCP connector.

pub const VERSION: &str = "0.5.0.0";

pub mod agent_hub;
pub mod audit;
pub mod connections;
pub mod evaluator;
pub mod evidence;
pub mod fleet;
pub mod internal_bridge;
pub mod mcp_gateway;
pub mod mcp_server;
pub mod providers;
pub mod routes;
pub mod settings;
pub mod store;
pub mod transport;
pub mod vault;
pub mod worker;

#[cfg(test)]
mod version_check {
    #[test]
    fn version_matches_version_file() {
        assert_eq!(super::VERSION, include_str!("../VERSION").trim());
    }
}
