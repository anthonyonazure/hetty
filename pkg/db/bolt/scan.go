package bolt

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"

	"github.com/oklog/ulid"
	bolt "go.etcd.io/bbolt"

	"github.com/dstotijn/hetty/pkg/scan"
)

var ErrScanIssuesBucketNotFound = errors.New("bolt: scan issues bucket not found")

var scanIssuesBucketName = []byte("scan_issues")

func scanIssuesBucket(tx *bolt.Tx, projectID ulid.ULID) (*bolt.Bucket, error) {
	pb, err := projectBucket(tx, projectID[:])
	if err != nil {
		return nil, err
	}

	b := pb.Bucket(scanIssuesBucketName)
	if b == nil {
		return nil, ErrScanIssuesBucketNotFound
	}

	return b, nil
}

// StoreIssue persists a scan issue.
func (db *Database) StoreIssue(ctx context.Context, issue scan.Issue) error {
	buf := bytes.Buffer{}

	if err := gob.NewEncoder(&buf).Encode(issue); err != nil {
		return fmt.Errorf("bolt: failed to encode scan issue: %w", err)
	}

	err := db.bolt.Update(func(tx *bolt.Tx) error {
		b, err := createNestedBucket(tx, projectsBucketName, issue.ProjectID[:], scanIssuesBucketName)
		if err != nil {
			return fmt.Errorf("failed to get scan issues bucket: %w", err)
		}

		if err := b.Put(issue.ID[:], buf.Bytes()); err != nil {
			return fmt.Errorf("failed to put scan issue: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("bolt: failed to commit transaction: %w", err)
	}

	return nil
}

// FindIssues returns all stored issues for a project, newest first.
func (db *Database) FindIssues(ctx context.Context, projectID ulid.ULID) ([]scan.Issue, error) {
	issues := make([]scan.Issue, 0)

	err := db.bolt.View(func(tx *bolt.Tx) error {
		b, err := scanIssuesBucket(tx, projectID)
		if errors.Is(err, ErrScanIssuesBucketNotFound) ||
			errors.Is(err, ErrProjectBucketNotFound) ||
			errors.Is(err, ErrProjectsBucketNotFound) {
			// No issues stored yet.
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get scan issues bucket: %w", err)
		}

		return b.ForEach(func(_, raw []byte) error {
			var issue scan.Issue
			if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&issue); err != nil {
				return fmt.Errorf("failed to decode scan issue: %w", err)
			}
			issues = append(issues, issue)

			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: failed to find scan issues: %w", err)
	}

	// Reverse so the newest issues appear first (ULID keys sort ascending).
	for i, j := 0, len(issues)-1; i < j; i, j = i+1, j-1 {
		issues[i], issues[j] = issues[j], issues[i]
	}

	return issues, nil
}

// FindIssueByID returns a single stored issue.
func (db *Database) FindIssueByID(ctx context.Context, projectID, id ulid.ULID) (scan.Issue, error) {
	var issue scan.Issue

	err := db.bolt.View(func(tx *bolt.Tx) error {
		b, err := scanIssuesBucket(tx, projectID)
		if err != nil {
			return err
		}

		raw := b.Get(id[:])
		if raw == nil {
			return errors.New("bolt: scan issue not found")
		}

		return gob.NewDecoder(bytes.NewReader(raw)).Decode(&issue)
	})
	if err != nil {
		return scan.Issue{}, fmt.Errorf("bolt: failed to find scan issue by ID: %w", err)
	}

	return issue, nil
}

// ClearIssues deletes all issues for a project.
func (db *Database) ClearIssues(ctx context.Context, projectID ulid.ULID) error {
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		pb, err := projectBucket(tx, projectID[:])
		if errors.Is(err, ErrProjectBucketNotFound) || errors.Is(err, ErrProjectsBucketNotFound) {
			return nil
		}
		if err != nil {
			return err
		}

		if pb.Bucket(scanIssuesBucketName) == nil {
			return nil
		}

		return pb.DeleteBucket(scanIssuesBucketName)
	})
	if err != nil {
		return fmt.Errorf("bolt: failed to clear scan issues: %w", err)
	}

	return nil
}
