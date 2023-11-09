# aws-sign-v4
[![Crates.io](https://img.shields.io/crates/v/aws-sign-v4.svg)](https://crates.io/crates/aws-sign-v4)

Use this crate to generate an AUTHORIZATION header for [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signing-aws-api-requests.html) services.

# Examples

## Example AWS S3 GET request
Example usage with reqwest:
```rust
const S3_ACCESS: &str = "my-access-key";
const S3_SECRET: &str = "my-secret-key";

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let datetime = chrono::Utc::now();
    let url = "https://myHost/s3-bucket-url";
    let mut headers = reqwest::header::HeaderMap::new();

    headers.insert(
        "X-Amz-Date",
        datetime
            .format("%Y%m%dT%H%M%SZ")
            .to_string()
            .parse()
            .unwrap(),
    );
    headers.insert("host", "myHost".parse().unwrap());

    let s = aws_sign_v4::AwsSign::new(
        "GET",
        url,
        &datetime,
        &headers,
        "us-east-1",
        &S3_ACCESS,
        &S3_SECRET,
        "s3",
        ""
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

## Example AWS graphql POST request
Example usage with reqwest:
```rust
const S3_ACCESS: &str = "my-access-key";
const S3_SECRET: &str = "my-secret-key";

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let datetime = chrono::Utc::now();
    let url = "https://myHost/s3-bucket-url";
    let mut headers = reqwest::header::HeaderMap::new();

    headers.insert(
        "X-Amz-Date",
        datetime
            .format("%Y%m%dT%H%M%SZ")
            .to_string()
            .parse()
            .unwrap(),
    );
    headers.insert("host", "myHost".parse().unwrap());

    let s = aws_sign_v4::AwsSign::new(
        "POST",
        url,
        &datetime,
        &headers,
        "us-east-1",
        &S3_ACCESS,
        &S3_SECRET,
        "execute-api",
        ""
    );
    let signature = s.sign();
    println!("{:#?}", signature);
    headers.insert(reqwest::header::AUTHORIZATION, signature.parse().unwrap());

    let client = reqwest::Client::new();
    let res = client
        .get(url)
        .headers(headers.to_owned())
        .body(r#"{"query":"query test_q { mynode { id }} ","variables":{},"operationName":"test_q"}"#)
        .send()
        .await?;

    println!("Status: {}", res.status());
    let body = res.text().await?;
    println!("Response Body:\n{}", body);
    Ok(())
}
```

## Example AWS SNS publish request

Example usage with reqwest:

```rust
const S3_ACCESS: &str = "my-access-key";
const S3_SECRET: &str = "my-secret-key";
const S3_TOPIC_ARN: &str = "arn:aws:sns:eu-west-1:xxx:xxx";
const S3_REGION: &str = "eu-west-1";

#[tokio::main]
async fn main() {
    let hostname = format!("sns.{}.amazonaws.com", S3_REGION);
    let url = format!("https://{}/", hostname);
    let ts = chrono::Utc::now();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("host", hostname.parse().unwrap());
    headers.insert(
        "X-Amz-Date",
        ts.format("%Y%m%dT%H%M%SZ").to_string().parse().unwrap(),
    );
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );

    let body = [
        ("Action", "Publish"),
        ("TopicArn", S3_TOPIC_ARN),
        ("MessageAttributes.entry.1.Name", "AttributeExample"),
        ("MessageAttributes.entry.1.Value.DataType", "String"),
        ("MessageAttributes.entry.1.Value.StringValue", "AttributeExampleValue"),
        ("Message", "Hello world!"),
    ];
    let body = serde_urlencoded::to_string(body).unwrap();

    let s = aws_sign_v4::AwsSign::new(
        "POST", &url, &ts, &headers, &S3_REGION, &S3_ACCESS, &S3_SECRET, "sns", &body,
    )
    .sign();

    headers.insert(reqwest::header::AUTHORIZATION, s.parse().unwrap());

    let client = reqwest::Client::new();
    let res = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .unwrap();
    res.error_for_status().unwrap();
}
```

# To migrate code from 0.1.x to 0.2.x:

```
# Before (0.1.1):
let s = aws_sign_v4::AwsSign::new(
        "GET",
        url,
        &datetime,
        &headers,
        "us-east-1",
        &S3_ACCESS,
        &S3_SECRET,
    );

# After (0.2.0):
let s = aws_sign_v4::AwsSign::new(
        "GET",
        url,
        &datetime,
        &headers,
        "us-east-1",
        &S3_ACCESS,
        &S3_SECRET,
        "s3", // <- explicitly add "s3", since 0.1.x only supported "s3"
        "", // <-- body can be ignored for "s3" service GETs
    );

```

# References

- [AWS General Reference -> Signing AWS API requests](https://docs.aws.amazon.com/general/latest/gr/signing-aws-api-requests.html)
- [Amazon Simple Storage Service Api Reference -> Authenticating Requests (AWS Signature Version 4)](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
- [AWS General Reference -> Service endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/aws-service-information.html) - to look up "service" names and codes