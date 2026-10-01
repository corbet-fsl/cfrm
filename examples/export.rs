fn main() {
    let path = std::path::Path::new("generated");
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(path.join("client.ts"), cfrm::typescript()).unwrap();
    std::fs::write(path.join("openapi.json"), serde_json::to_vec_pretty(&cfrm::openapi()).unwrap()).unwrap();
}
