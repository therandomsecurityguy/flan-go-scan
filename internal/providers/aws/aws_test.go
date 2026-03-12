package aws

import (
	"reflect"
	"testing"
	"time"
)

func TestBuildInventorySnapshot(t *testing.T) {
	snapshot := BuildInventorySnapshot(time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC), []Asset{
		{AccountID: "123456789012", Region: "us-west-2", Service: "ec2", AssetType: "instance", ResourceID: "i-1", Name: "api", Target: "api.example.net", Public: true, Source: "aws"},
		{AccountID: "123456789012", Region: "us-east-1", Service: "cloudfront", AssetType: "distribution", ResourceID: "dist-1", Target: "d123.cloudfront.net", Public: true, Source: "aws"},
	}, DiscoverOptions{
		Regions: []string{"us-west-2", "us-east-1"},
		Include: []string{"*.example.net"},
		Exclude: []string{"internal.example.net"},
	})

	if snapshot.Source != "aws" {
		t.Fatalf("unexpected source: %s", snapshot.Source)
	}
	if snapshot.AssetCount != 2 {
		t.Fatalf("unexpected asset count: %d", snapshot.AssetCount)
	}
	if !reflect.DeepEqual(snapshot.Accounts, []string{"123456789012"}) {
		t.Fatalf("unexpected accounts: %v", snapshot.Accounts)
	}
	if !reflect.DeepEqual(snapshot.Regions, []string{"us-east-1", "us-west-2"}) {
		t.Fatalf("unexpected regions: %v", snapshot.Regions)
	}
}

func TestDiffInventory(t *testing.T) {
	previous := InventorySnapshot{
		GeneratedAt: "2026-03-11T11:00:00Z",
		Source:      "aws",
		Assets: []Asset{
			{AccountID: "123456789012", Region: "us-west-2", Service: "ec2", AssetType: "instance", ResourceID: "i-1", Name: "api", Target: "old.example.net", Public: true, Source: "aws"},
			{AccountID: "123456789012", Region: "us-west-2", Service: "ec2", AssetType: "instance", ResourceID: "i-2", Name: "legacy", Target: "legacy.example.net", Public: true, Source: "aws"},
		},
	}
	current := InventorySnapshot{
		GeneratedAt: "2026-03-11T12:00:00Z",
		Source:      "aws",
		Assets: []Asset{
			{AccountID: "123456789012", Region: "us-west-2", Service: "ec2", AssetType: "instance", ResourceID: "i-1", Name: "api", Target: "new.example.net", Public: true, Source: "aws"},
			{AccountID: "123456789012", Region: "us-east-1", Service: "cloudfront", AssetType: "distribution", ResourceID: "dist-1", Target: "d123.cloudfront.net", Public: true, Source: "aws"},
		},
	}

	diff := DiffInventory(time.Date(2026, 3, 11, 12, 0, 0, 0, time.UTC), previous, current)
	if diff.AddedCount != 1 {
		t.Fatalf("unexpected added count: %d", diff.AddedCount)
	}
	if diff.RemovedCount != 1 {
		t.Fatalf("unexpected removed count: %d", diff.RemovedCount)
	}
	if diff.ChangedCount != 1 {
		t.Fatalf("unexpected changed count: %d", diff.ChangedCount)
	}
}

func TestTargetsFromDiff(t *testing.T) {
	diff := InventoryDiff{
		Added: []Asset{
			{Target: "api.example.net"},
			{Target: "api.example.net"},
		},
		Changed: []AssetChange{
			{After: Asset{Target: "1.1.1.1"}},
		},
	}

	got := TargetsFromDiff(diff)
	want := []string{"1.1.1.1", "api.example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected targets: got %v want %v", got, want)
	}
}

func TestIsAllowedTarget(t *testing.T) {
	if isAllowedTarget("10.0.0.1", nil, nil) {
		t.Fatal("expected private target to be excluded")
	}
	if !isAllowedTarget("api.example.net", []string{"*.example.net"}, nil) {
		t.Fatal("expected include match to be allowed")
	}
	if isAllowedTarget("internal.example.net", nil, []string{"internal.example.net"}) {
		t.Fatal("expected exclude match to be denied")
	}
}
