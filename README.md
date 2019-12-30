# aws-sign-v4
[![Crates.io](https://img.shields.io/crates/v/aws-sign-v4.svg)](https://crates.io/crates/aws-sign-v4)

Use this crate to generate an AUTHORIZATION header for AWS Signature Version 4 services.

## Example
Example usage with reqwest:

```rust
const S3_ACCESS: &str = "my-access-key";
const S3_SECRET: &str = "my-secret-key";

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let datetime = chrono::Utc::now();
    let url = "https://s3-bucket-url";
    let mut headers = reqwest::header::HeaderMap::new();

    headers.insert(
        "X-Amz-Date",
        datetime
            .format("%Y%m%dT%H%M%SZ")
            .to_string()
            .parse()
            .unwrap(),
    );
    headers.insert("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
    headers.insert("host", "my-host".parse().unwrap());

    let s = aws_sign_v4::AwsSign::new(
        "GET",
        url,
        &datetime,
        &headers,
        "us-east-1",
        &S3_ACCESS,
        &S3_SECRET,
    );
    let signature = s.sign();
    println!("{:#?}", signature);
    headers.insert(reqwest::header::AUTHORIZATION, signature.parse().unwrap());

    let client = reqwest::Client::new();
    let res = client
        .get(url)
        .headers(headers.to_owned())
        .body("")
        .send()
        .await?;

    println!("Status: {}", res.status());
    let body = res.text().await?;
    println!("Body:\n\n{}", body);
    Ok(())
}
```
