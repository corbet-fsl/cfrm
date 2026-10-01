use super::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wire_registry_and_refusal_are_identical_in_the_browser() {
    let possession = Possession {
        session: vec![1],
        request_nonce: vec![2],
        signature: vec![3],
    };
    let room = RoomInput {
        room_pass: vec![5],
        command: vec![4],
    };
    let requests = vec![
        Request::Challenge(ChallengeInput {
            credential: vec![1],
        }),
        Request::Enter(EnterInput {
            challenge: vec![1],
            signature: vec![2],
            publication: vec![3],
            record_proof: vec![4],
        }),
        Request::Replace(ReplaceInput {
            possession: possession.clone(),
            expected_revision: vec![1],
            publication: vec![2],
            record_proof: vec![3],
        }),
        Request::Heartbeat(HeartbeatInput {
            possession: possession.clone(),
            expected_revision: vec![1],
        }),
        Request::Depart(DepartInput {
            possession: possession.clone(),
        }),
        Request::Search(SearchInput {
            possession: possession.clone(),
            cursor: None,
            page_size: 10,
        }),
        Request::Watch(WatchInput {
            possession: possession.clone(),
            cursor: vec![1],
        }),
        Request::Ciphertext(CiphertextInput {
            possession,
            owner: vec![1],
            revision: vec![2],
        }),
        Request::RoomOrder(room.clone()),
        Request::RoomRelay(room.clone()),
        Request::RoomResume(room.clone()),
        Request::RoomHandover(room),
    ];
    let names = actions().into_iter().map(|a| a.name).collect::<Vec<_>>();
    assert_eq!(
        requests.iter().map(|r| r.info().name).collect::<Vec<_>>(),
        names
    );
    for request in requests {
        let name = request.info().name;
        assert!((request.info().input_schema)().is_object());
        if name.starts_with("room_") {
            assert_eq!(request.info().requirement, Requirement::AnonymousRoomPass);
        }
        let bytes = serde_json::to_vec(&Call::new(request)).unwrap();
        assert_eq!(
            execute_tool(name, &bytes, 4096),
            Err(ErrorCode::AuthorityUnavailable)
        );
        assert_eq!(
            execute_tool("unknown", &bytes, 4096),
            Err(ErrorCode::InvalidRequest)
        );
        let decoded = Call::decode(&bytes, 4096).unwrap();
        assert_eq!(decoded.request.info().name, name);
        assert!(matches!(
            execute(&decoded),
            Err(ErrorCode::AuthorityUnavailable)
        ));
    }
    let spec = openapi();
    let tools = mcp_tools();
    assert_eq!(tools["tools"].as_array().unwrap().len(), names.len());
    let ts = typescript();
    for name in names {
        assert!(ts.contains(name));
        assert!(spec["paths"][format!("/v1/{name}")]["post"].is_object());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wire_decoder_refuses_duplicate_unknown_and_unbounded_input() {
    for bytes in [
        br#"{"version":1,"version":1,"request":{"action":"challenge","input":{"credential":[]}}}"#
            .as_slice(),
        br#"{"version":1,"request":{"action":"challenge","input":{"credential":[],"extra":true}}}"#,
        br#"{"version":1,"request":{"action":"unknown","input":{}}}"#,
        br#"{"version":1,"request":{"action":"challenge","input":{"credential":[256]}}}"#,
    ] {
        assert_eq!(
            execute_tool("challenge", bytes, 4096),
            Err(ErrorCode::InvalidRequest)
        );
        assert!(matches!(
            Call::decode(bytes, 4096),
            Err(ErrorCode::InvalidRequest)
        ));
    }
    assert!(matches!(Call::decode(&[0; 8], 7), Err(ErrorCode::TooLarge)));
    let mut call = Call::new(Request::Challenge(ChallengeInput { credential: vec![] }));
    call.version = 2;
    assert!(matches!(
        Call::decode(&serde_json::to_vec(&call).unwrap(), 4096),
        Err(ErrorCode::UnsupportedVersion)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn room_api_refuses_authenticated_presence_bindings() {
    let bytes=br#"{"version":1,"request":{"action":"room_order","input":{"possession":{"session":[1],"request_nonce":[2],"signature":[3]},"room_pass":[4],"command":[5]}}}"#;
    assert!(matches!(
        Call::decode(bytes, 4096),
        Err(ErrorCode::InvalidRequest)
    ));
    assert_eq!(
        execute_tool("room_order", bytes, 4096),
        Err(ErrorCode::InvalidRequest)
    );
    assert_eq!(
        execute_tool("challenge", &[0; 8], 7),
        Err(ErrorCode::TooLarge)
    );
}
