#![cfg(not(target_arch = "wasm32"))]

#[test]
fn actual_mcp_sdk_accepts_the_owner_catalog_and_refusal_output() {
    let catalog: rmcp::model::ListToolsResult =
        serde_json::from_value(cfrm::mcp_tools()).unwrap();
    assert_eq!(catalog.tools.len(), cfrm::actions().len());
    for (tool, action) in catalog.tools.iter().zip(cfrm::actions()) {
        assert_eq!(tool.name, action.name);
        assert_eq!(tool.input_schema["type"], "object");
    }
    let failure = cfrm::Failure {
        error: cfrm::ErrorCode::AuthorityUnavailable,
    };
    let response = rmcp::model::CallToolResult::structured_error(
        serde_json::to_value(failure).unwrap(),
    );
    assert_eq!(response.is_error, Some(true));
    assert_eq!(response.structured_content.unwrap()["error"], "authority_unavailable");
}
