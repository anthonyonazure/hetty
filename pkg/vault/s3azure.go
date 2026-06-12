package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpClient is shared by the cloud backends (overridable in tests).
var httpClient = &http.Client{Timeout: 60 * time.Second}

// nowUTC is overridable in tests for deterministic signatures.
var nowUTC = func() time.Time { return time.Now().UTC() }

// --- S3-compatible (AWS Signature V4) --------------------------------------

type s3Backend struct {
	endpoint  string // host base, e.g. https://s3.amazonaws.com
	region    string
	bucket    string
	accessKey string
	secretKey string
}

func newS3(cfg Config) *s3Backend {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://s3.amazonaws.com"
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	return &s3Backend{
		endpoint:  strings.TrimRight(endpoint, "/"),
		region:    region,
		bucket:    cfg.Bucket,
		accessKey: cfg.AccessKey,
		secretKey: cfg.SecretKey,
	}
}

func (b *s3Backend) Kind() string { return "s3" }

func (b *s3Backend) Put(ctx context.Context, key string, data []byte, contentType string) (string, error) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	url := fmt.Sprintf("%s/%s/%s", b.endpoint, b.bucket, strings.TrimLeft(key, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)

	b.sign(req, data)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault(s3): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("vault(s3): %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return url, nil
}

func (b *s3Backend) sign(req *http.Request, payload []byte) {
	t := nowUTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	payloadHash := hexSHA256(payload)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("Host", req.URL.Host)

	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.URL.Host, payloadHash, amzDate)

	canonicalURI := req.URL.EscapedPath()
	canonicalRequest := strings.Join([]string{
		req.Method, canonicalURI, req.URL.RawQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, b.region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+b.secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, b.region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		b.accessKey, scope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
}

// --- Azure Blob Storage (SharedKey) ----------------------------------------

type azureBackend struct {
	account   string
	container string
	key       []byte // decoded account key
	endpoint  string // optional override (for tests)
}

func newAzure(cfg Config) *azureBackend {
	key, _ := base64.StdEncoding.DecodeString(cfg.AccountKey)
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.blob.core.windows.net", cfg.Account)
	}
	return &azureBackend{
		account:   cfg.Account,
		container: cfg.Container,
		key:       key,
		endpoint:  strings.TrimRight(endpoint, "/"),
	}
}

func (b *azureBackend) Kind() string { return "azure" }

func (b *azureBackend) Put(ctx context.Context, key string, data []byte, contentType string) (string, error) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	blobPath := fmt.Sprintf("/%s/%s", b.container, strings.TrimLeft(key, "/"))
	url := b.endpoint + blobPath

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	amzDate := nowUTC().Format(http.TimeFormat)
	req.Header.Set("x-ms-date", amzDate)
	req.Header.Set("x-ms-version", "2021-08-06")
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = int64(len(data))

	b.sign(req, blobPath, len(data), contentType)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault(azure): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("vault(azure): %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return url, nil
}

func (b *azureBackend) sign(req *http.Request, resourcePath string, length int, contentType string) {
	// Canonicalized headers: all x-ms-* sorted, "header:value\n".
	canonHeaders := fmt.Sprintf("x-ms-blob-type:BlockBlob\nx-ms-date:%s\nx-ms-version:2021-08-06\n",
		req.Header.Get("x-ms-date"))

	canonResource := fmt.Sprintf("/%s%s", b.account, resourcePath)

	// PUT signature string (the blank lines are unused headers per Azure spec).
	stringToSign := strings.Join([]string{
		"PUT",            // verb
		"",               // Content-Encoding
		"",               // Content-Language
		fmt.Sprint(length), // Content-Length
		"",               // Content-MD5
		contentType,      // Content-Type
		"",               // Date
		"",               // If-Modified-Since
		"",               // If-Match
		"",               // If-None-Match
		"",               // If-Unmodified-Since
		"",               // Range
		canonHeaders + canonResource,
	}, "\n")

	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", b.account, sig))
}

// --- shared crypto helpers -------------------------------------------------

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
