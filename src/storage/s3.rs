use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{
    self,
    config::{Credentials, SharedCredentialsProvider},
    primitives::ByteStream,
    Client,
};
use anyhow::{Context, Result};
use tracing::{debug};

pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: Option<String>,
    pub access_key: String,
    pub secret_key: String
}

pub struct S3Client {
    client: Client,
    bucket: String,
}

impl S3Client {
    pub async fn new(cfg: S3Config) -> Result<Self> {
        let credentials = Credentials::new(
            &cfg.access_key,
            &cfg.secret_key,
            None, // session token
            None, // expiry
            "S3Client",
        );

        let region = match &cfg.region {
            Some(r) => Region::new(r.clone()),
            None => Region::new("auto"),
        };

        let config = aws_config::defaults(BehaviorVersion::v2025_08_07())
            .region(region)
            .credentials_provider(SharedCredentialsProvider::new(credentials))
            .endpoint_url(&cfg.endpoint)
            .load()
            .await;

        let client = Client::new(&config);

        // Test the connection
        Self::test_connection(&client, &cfg.bucket).await?;

        Ok(Self {
            client,
            bucket: cfg.bucket,
        })
    }

    async fn test_connection(client: &Client, bucket: &str) -> Result<()> {
        client
            .head_bucket()
            .bucket(bucket)
            .send()
            .await
            .with_context(|| format!("Failed to connect to bucket: {}", bucket))?;
        debug!("Successfully connected to S3 bucket: {}", bucket);
        Ok(())
    }

    pub async fn get_content(&self, key: &str) -> Result<Option<String>> {
        debug!("Getting object: {} from bucket: {}", key, self.bucket);
        
        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to get object: {}", key))?;

        let bytes =response
            .body
            .collect()
            .await?
            .into_bytes();
        let content = String::from_utf8(bytes.to_vec()).context("Failed to convert bytes to string")?;

        debug!("Successfully retrieved object: {} ({} bytes)", key, content.len());
        Ok(Some(content))
    }

    pub async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        debug!("Getting object bytes: {} from bucket: {}", key, self.bucket);
        
        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to get object: {}", key))?;

        let bytes = response
            .body
            .collect()
            .await
            .context("Failed to collect response body")?
            .to_vec();

        debug!("Successfully retrieved object bytes: {} ({} bytes)", key, bytes.len());
        Ok(Some(bytes))
    }

    pub async fn put_content(&self, key: &str, content: &str) -> Result<()> {
        debug!("Putting object: {} to bucket: {} ({} bytes)", key, self.bucket, content.len());
        
        let body = ByteStream::from(content.as_bytes().to_vec());
        
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .with_context(|| format!("Failed to put object: {}", key))?;

        debug!("Successfully uploaded object: {}", key);
        Ok(())
    }

    pub async fn put_bytes(&self, key: &str, bytes: &[u8]) -> Result<()> {
        debug!("Putting object bytes: {} to bucket: {} ({} bytes)", key, self.bucket, bytes.len());
        
        let body = ByteStream::from(bytes.to_vec());
        
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .with_context(|| format!("Failed to put object: {}", key))?;

        debug!("Successfully uploaded object bytes: {}", key);
        Ok(())
    }

    pub async fn delete_content(&self, key: &str) -> Result<()> {
        debug!("Deleting object: {} from bucket: {}", key, self.bucket);
        
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to delete object: {}", key))?;

        debug!("Successfully deleted object: {}", key);
        Ok(())
    }

    pub async fn list_objects(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        debug!("Listing objects in bucket: {} with prefix: {:?}", self.bucket, prefix);
        
        let mut request = self.client
            .list_objects_v2()
            .bucket(&self.bucket);

        if let Some(p) = prefix {
            request = request.prefix(p);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to list objects in bucket: {}", self.bucket))?;

        let keys: Vec<String> = response
            .contents
            .unwrap_or_default()
            .into_iter()
            .filter_map(|obj| obj.key)
            .collect();

        debug!("Found {} objects in bucket: {}", keys.len(), self.bucket);
        Ok(keys)
    }

    pub async fn object_exists(&self, key: &str) -> Result<bool> {
        debug!("Checking if object exists: {} in bucket: {}", key, self.bucket);
        
        match self.client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => {
                debug!("Object exists: {}", key);
                Ok(true)
            }
            Err(e) => {
                if e.as_service_error().is_some() && e.to_string().contains("404") {
                    debug!("Object does not exist: {}", key);
                    Ok(false)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    pub async fn get_object_size(&self, key: &str) -> Result<Option<u64>> {
        debug!("Getting object size: {} from bucket: {}", key, self.bucket);
        
        let response = self.client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("Failed to get object size: {}", key))?;

        let size = response.content_length().map(|s| s as u64);
        debug!("Object size for {}: {:?} bytes", key, size);
        Ok(size)
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub async fn copy_object(&self, source_key: &str, dest_key: &str) -> Result<()> {
        debug!("Copying object {} to {} in bucket: {}", source_key, dest_key, self.bucket);
        
        let copy_source = format!("{}/{}", self.bucket, source_key);
        
        self.client
            .copy_object()
            .bucket(&self.bucket)
            .copy_source(copy_source)
            .key(dest_key)
            .send()
            .await
            .with_context(|| format!("Failed to copy object from {} to {}", source_key, dest_key))?;

        debug!("Successfully copied object {} to {}", source_key, dest_key);
        Ok(())
    }
}