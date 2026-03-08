#![cfg(feature = "tokio")]

use supertar::tokio::Archive;
use tokio::io::AsyncReadExt;

// Re-use the same tar-building helpers via a shared module would be ideal,
// but for simplicity we inline minimal helpers here.

fn create_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut builder = tar::Builder::new(Vec::new());
    for (path, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, *content).unwrap();
    }
    let tar_data = builder.into_inner().unwrap();

    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn test_async_new_and_read() {
    let compressed = create_tar_gz(&[
        ("hello.txt", b"hello world"),
        ("data.bin", &[1, 2, 3, 4, 5]),
    ]);
    let cursor = std::io::Cursor::new(compressed);

    let mut archive = Archive::new(cursor).await.unwrap();

    assert_eq!(archive.list().len(), 2);
    assert_eq!(archive.read_file("hello.txt").await.unwrap(), b"hello world");
    assert_eq!(archive.read_file("data.bin").await.unwrap(), &[1, 2, 3, 4, 5]);
}

#[tokio::test]
async fn test_async_from_reader() {
    let compressed = create_tar_gz(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
    let len = compressed.len() as u64;
    let cursor = std::io::Cursor::new(compressed);

    let archive = Archive::from_reader(cursor, len).await.unwrap();

    assert_eq!(archive.list().len(), 2);
    assert_eq!(archive.entry("a.txt").unwrap().size, 5);
    assert_eq!(archive.entry("b.txt").unwrap().size, 4);
}

#[tokio::test]
async fn test_async_read_file_range() {
    let content: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let compressed = create_tar_gz(&[("data.bin", content.as_slice())]);
    let cursor = std::io::Cursor::new(compressed);

    let mut archive = Archive::new(cursor).await.unwrap();

    let range = archive.read_file_range("data.bin", 5000, 2000).await.unwrap();
    assert_eq!(range.len(), 2000);
    assert_eq!(&range, &content[5000..7000]);
}

#[tokio::test]
async fn test_async_open_streaming() {
    let compressed = create_tar_gz(&[("msg.txt", b"streamed content")]);
    let cursor = std::io::Cursor::new(compressed);

    let mut archive = Archive::new(cursor).await.unwrap();
    let mut reader = archive.open("msg.txt").await.unwrap();

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"streamed content");
}

#[tokio::test]
async fn test_async_open_small_reads() {
    let content: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let compressed = create_tar_gz(&[("data.bin", content.as_slice())]);
    let cursor = std::io::Cursor::new(compressed);

    let mut archive = Archive::new(cursor).await.unwrap();
    let mut reader = archive.open("data.bin").await.unwrap();

    let mut result = Vec::new();
    let mut small_buf = [0u8; 7];
    loop {
        let n = reader.read(&mut small_buf).await.unwrap();
        if n == 0 {
            break;
        }
        result.extend_from_slice(&small_buf[..n]);
    }
    assert_eq!(result, content);
}

#[tokio::test]
async fn test_async_open_matches_read_file() {
    let content: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
    let compressed = create_tar_gz(&[("big.bin", content.as_slice())]);
    let cursor = std::io::Cursor::new(compressed.clone());

    let mut archive = Archive::new(cursor).await.unwrap();
    let via_read_file = archive.read_file("big.bin").await.unwrap();

    let mut via_open = Vec::new();
    {
        let mut reader = archive.open("big.bin").await.unwrap();
        reader.read_to_end(&mut via_open).await.unwrap();
    }

    assert_eq!(via_read_file, via_open);
}

#[tokio::test]
async fn test_async_into_parts_from_parts() {
    let compressed = create_tar_gz(&[("f.txt", b"data")]);
    let cursor = std::io::Cursor::new(compressed);

    let archive = Archive::new(cursor).await.unwrap();
    let (reader, index) = archive.into_parts();

    let mut archive2 = Archive::from_parts(reader, index);
    assert_eq!(archive2.read_file("f.txt").await.unwrap(), b"data");
}

#[tokio::test]
async fn test_async_file_not_found() {
    let compressed = create_tar_gz(&[("exists.txt", b"data")]);
    let cursor = std::io::Cursor::new(compressed);

    let mut archive = Archive::new(cursor).await.unwrap();
    let result = archive.read_file("nonexistent.txt").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_async_io_copy() {
    let compressed = create_tar_gz(&[("msg.txt", b"hello async")]);
    let cursor = std::io::Cursor::new(compressed);

    let mut archive = Archive::new(cursor).await.unwrap();
    let mut reader = archive.open("msg.txt").await.unwrap();
    let mut dest = Vec::new();
    tokio::io::copy(&mut reader, &mut dest).await.unwrap();
    assert_eq!(dest, b"hello async");
}
