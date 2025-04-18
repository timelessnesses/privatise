mod test_api {
    use super::super::api::File;
    use std::io::Read;

    #[tokio::test]
    async fn test_upload() {
        let t = chrono::Local::now();
        let f = File::upload(
            std::path::Path::new("test.png"),
            chrono::Duration::seconds(1000),
        )
        .await
        .unwrap();
        dbg!(&f);
        assert!(t + chrono::Duration::seconds(1000) < f.expires_at.unwrap());
        assert_eq!(f.file_name.unwrap(), "test");
        assert_eq!(f.file_ext.unwrap(), "png");
        assert!(f.id.len() > 0);
        assert!(f.key.is_some());
        assert!(f.nonce.is_some());
    }

    #[tokio::test]
    async fn test_upload_encrypt_client_side() {
        let t = chrono::Local::now();
        let f = File::upload_encrypt_client_side(
            std::path::Path::new("test.png"),
            chrono::Duration::seconds(1000),
        )
        .await
        .unwrap();
        dbg!(&f);
        assert!(t + chrono::Duration::seconds(1000) < f.expires_at.unwrap());
        assert_eq!(f.file_name.as_ref().unwrap(), "test");
        assert_eq!(f.file_ext.as_ref().unwrap(), "png");
        assert!(f.id.len() > 0);
        assert!(f.key.is_some());
        assert!(f.nonce.is_some());
        f.delete(None, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_upload_buffer() {
        let t = chrono::Local::now();
        let f = File::upload_buffer(
            random_bytes::<1024>(&mut rand::rng()).to_vec(),
            "test".to_owned(),
            "png".to_owned(),
            chrono::Duration::seconds(1000),
        )
        .await
        .unwrap();
        dbg!(&f);
        assert!(t + chrono::Duration::seconds(1000) < f.expires_at.unwrap());
        assert_eq!(f.file_name.as_ref().unwrap(), "test");
        assert_eq!(f.file_ext.as_ref().unwrap(), "png");
        assert!(f.id.len() > 0);
        assert!(f.key.is_some());
        assert!(f.nonce.is_some());
        f.delete(None, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_upload_buffer_encrypt_client_side() {
        let t = chrono::Local::now();
        let f = File::upload_buffer_encrypt_client_side(
			random_bytes::<1024>(&mut rand::rng()).to_vec(),
            "test".to_owned(),
            "png".to_owned(),
            chrono::Duration::seconds(1000),
        )
        .await
        .unwrap();
        dbg!(&f);
        assert!(t + chrono::Duration::seconds(1000) < f.expires_at.unwrap());
        assert_eq!(f.file_name.as_ref().unwrap(), "test");
        assert_eq!(f.file_ext.as_ref().unwrap(), "png");
        assert!(f.id.len() > 0);
        assert!(f.key.is_some());
        assert!(f.nonce.is_some());
    }

    #[tokio::test]
    async fn test_read_client_side() {
        let t = chrono::Local::now();
        let f = File::upload_encrypt_client_side(
            std::path::Path::new("test.png"),
            chrono::Duration::seconds(1000),
        )
        .await
        .unwrap();
        let data = f.read(None, None).await.unwrap();
        assert!(t + chrono::Duration::seconds(1000) < f.expires_at.unwrap());
        assert_eq!(f.file_name.as_ref().unwrap(), "test");
        assert_eq!(f.file_ext.as_ref().unwrap(), "png");
        assert!(f.id.len() > 0);
        assert!(f.key.is_some());
        assert!(f.nonce.is_some());

        let mut file = std::fs::File::open("test.png").unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, data);

        f.delete(None, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_read_server_side() {
        let t = chrono::Local::now();
        let f = File::upload_encrypt_client_side(
            std::path::Path::new("test.png"),
            chrono::Duration::seconds(1000),
        )
        .await
        .unwrap();
        let data = f.read_server_side(None, None).await.unwrap();
        assert!(t + chrono::Duration::seconds(1000) < f.expires_at.unwrap());
        assert_eq!(f.file_name.as_ref().unwrap(), "test");
        assert_eq!(f.file_ext.as_ref().unwrap(), "png");
        assert!(f.id.len() > 0);
        assert!(f.key.is_some());
        assert!(f.nonce.is_some());

        let mut file = std::fs::File::open("test.png").unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, data);

        f.delete(None, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_info() {
        let t = chrono::Local::now();
        let f = File::upload_encrypt_client_side(
            std::path::Path::new("test.png"),
            chrono::Duration::seconds(1000),
        )
        .await
        .unwrap();
        let info = f.get_info().await.unwrap();
        assert!(t + chrono::Duration::seconds(1000) < f.expires_at.unwrap());
        assert_eq!(f.file_name.as_ref().unwrap(), "test");
        assert_eq!(f.file_ext.as_ref().unwrap(), "png");
        assert!(f.id.len() > 0);
        assert!(f.key.is_some());
        assert!(f.nonce.is_some());
        assert_eq!(info.id, f.id);
        assert_eq!(info.expires_at, f.expires_at.unwrap());
        assert_eq!(info.original_file_extension, "png");

        f.delete(None, None).await.unwrap();
    }

	fn random_bytes<const N: usize>(rng: &mut impl rand::Rng) -> [u8; N] {
		let mut bytes = [0u8; N];
		rng.fill_bytes(&mut bytes);
		bytes
	}
}
