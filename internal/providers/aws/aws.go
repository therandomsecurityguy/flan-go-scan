package aws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/errgroup"
)

const (
	defaultRegion    = "us-west-2"
	defaultSource    = "aws"
	maxRegionWorkers = 4
)

type Client struct {
	profile string
	timeout time.Duration
}

type Asset struct {
	AccountID  string `json:"account_id"`
	Region     string `json:"region,omitempty"`
	Service    string `json:"service"`
	AssetType  string `json:"asset_type"`
	ResourceID string `json:"resource_id"`
	Name       string `json:"name,omitempty"`
	Target     string `json:"target"`
	Public     bool   `json:"public"`
	Source     string `json:"source"`
}

type InventorySnapshot struct {
	GeneratedAt   string   `json:"generated_at"`
	Source        string   `json:"source"`
	Accounts      []string `json:"accounts,omitempty"`
	Regions       []string `json:"regions,omitempty"`
	RegionFilters []string `json:"region_filters,omitempty"`
	Include       []string `json:"include,omitempty"`
	Exclude       []string `json:"exclude,omitempty"`
	AssetCount    int      `json:"asset_count"`
	Assets        []Asset  `json:"assets"`
}

type InventoryDiff struct {
	GeneratedAt         string        `json:"generated_at"`
	Source              string        `json:"source"`
	PreviousGeneratedAt string        `json:"previous_generated_at,omitempty"`
	CurrentGeneratedAt  string        `json:"current_generated_at,omitempty"`
	AddedCount          int           `json:"added_count"`
	RemovedCount        int           `json:"removed_count"`
	ChangedCount        int           `json:"changed_count"`
	Added               []Asset       `json:"added,omitempty"`
	Removed             []Asset       `json:"removed,omitempty"`
	Changed             []AssetChange `json:"changed,omitempty"`
}

type AssetChange struct {
	Before Asset `json:"before"`
	After  Asset `json:"after"`
}

type DiscoverOptions struct {
	Regions []string
	Include []string
	Exclude []string
}

func NewClient(profile string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		profile: strings.TrimSpace(profile),
		timeout: timeout,
	}
}

func (c *Client) Discover(ctx context.Context, opts DiscoverOptions) ([]Asset, error) {
	baseCfg, err := c.loadConfig(ctx, defaultRegion)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	accountID, err := accountIDFromSTS(ctx, baseCfg)
	if err != nil {
		return nil, fmt.Errorf("get aws account id: %w", err)
	}

	regions := uniqueSortedValues(opts.Regions)
	if len(regions) == 0 {
		regions, err = enabledRegions(ctx, baseCfg)
		if err != nil {
			return nil, fmt.Errorf("list aws regions: %w", err)
		}
	}

	include := normalizePatterns(opts.Include)
	exclude := normalizePatterns(opts.Exclude)
	assets := make([]Asset, 0, 128)

	globalAssets, err := c.discoverGlobal(ctx, baseCfg, accountID, include, exclude)
	if err != nil {
		return nil, err
	}
	assets = append(assets, globalAssets...)

	regionalAssets, err := c.discoverRegional(ctx, accountID, regions, include, exclude)
	if err != nil {
		return nil, err
	}
	assets = append(assets, regionalAssets...)

	sort.Slice(assets, func(i, j int) bool {
		return assetKey(assets[i]) < assetKey(assets[j])
	})
	return dedupeAssets(assets), nil
}

func (c *Client) discoverGlobal(ctx context.Context, cfg aws.Config, accountID string, include, exclude []string) ([]Asset, error) {
	var assets []Asset
	for _, discover := range []func(context.Context, string, aws.Config, []string, []string) ([]Asset, error){
		discoverRoute53,
		discoverCloudFront,
		discoverS3Websites,
	} {
		serviceAssets, err := discover(ctx, accountID, cfg, include, exclude)
		if err != nil {
			return nil, err
		}
		assets = append(assets, serviceAssets...)
	}
	return assets, nil
}

func (c *Client) discoverRegional(ctx context.Context, accountID string, regions, include, exclude []string) ([]Asset, error) {
	var (
		mu     sync.Mutex
		assets []Asset
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxRegionWorkers)

	for _, region := range regions {
		region := region
		group.Go(func() error {
			cfg, err := c.loadConfig(groupCtx, region)
			if err != nil {
				return fmt.Errorf("load aws config for %s: %w", region, err)
			}
			discovered, err := discoverRegion(groupCtx, accountID, region, cfg, include, exclude)
			if err != nil {
				return err
			}
			mu.Lock()
			assets = append(assets, discovered...)
			mu.Unlock()
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}
	return assets, nil
}

func (c *Client) loadConfig(ctx context.Context, region string) (aws.Config, error) {
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(strings.TrimSpace(region)),
		awsconfig.WithHTTPClient(&http.Client{Timeout: c.timeout}),
	}
	if c.profile != "" {
		loadOptions = append(loadOptions, awsconfig.WithSharedConfigProfile(c.profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return aws.Config{}, err
	}
	return cfg, nil
}

func accountIDFromSTS(ctx context.Context, cfg aws.Config) (string, error) {
	client := sts.NewFromConfig(cfg)
	output, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(*output.Account), nil
}

func enabledRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	client := ec2.NewFromConfig(cfg)
	output, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: boolPtr(false),
	})
	if err != nil {
		return nil, err
	}
	regions := make([]string, 0, len(output.Regions))
	for _, region := range output.Regions {
		name := strings.TrimSpace(stringValue(region.RegionName))
		if name != "" {
			regions = append(regions, name)
		}
	}
	sort.Strings(regions)
	return regions, nil
}

func discoverRoute53(ctx context.Context, accountID string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := route53.NewFromConfig(cfg)
	paginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})
	var assets []Asset
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("route53 list hosted zones: %w", err)
		}
		for _, zone := range page.HostedZones {
			if zone.Config != nil && zone.Config.PrivateZone {
				continue
			}
			records, err := listRoute53Records(ctx, client, stringValue(zone.Id))
			if err != nil {
				return nil, err
			}
			for _, asset := range normalizeRoute53Records(accountID, zone, records, include, exclude) {
				assets = append(assets, asset)
			}
		}
	}
	return assets, nil
}

func listRoute53Records(ctx context.Context, client *route53.Client, zoneID string) ([]r53types.ResourceRecordSet, error) {
	paginator := route53.NewListResourceRecordSetsPaginator(client, &route53.ListResourceRecordSetsInput{
		HostedZoneId: stringPtr(strings.TrimPrefix(zoneID, "/hostedzone/")),
	})
	var records []r53types.ResourceRecordSet
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("route53 list record sets for zone %s: %w", zoneID, err)
		}
		records = append(records, page.ResourceRecordSets...)
	}
	return records, nil
}

func normalizeRoute53Records(accountID string, zone r53types.HostedZone, records []r53types.ResourceRecordSet, include, exclude []string) []Asset {
	var assets []Asset
	for _, record := range records {
		recordType := strings.ToUpper(string(record.Type))
		if !isScannableRecordType(recordType) {
			continue
		}
		name := normalizeTarget(stringValue(record.Name))
		if name == "" || isValidationRecordName(name) {
			continue
		}
		targets := route53Targets(record)
		for _, target := range targets {
			if !isAllowedTarget(target, include, exclude) {
				continue
			}
			assets = append(assets, Asset{
				AccountID:  accountID,
				Service:    "route53",
				AssetType:  "dns_record",
				ResourceID: fmt.Sprintf("%s:%s:%s:%s", strings.TrimPrefix(stringValue(zone.Id), "/hostedzone/"), name, recordType, target),
				Name:       name,
				Target:     target,
				Public:     true,
				Source:     defaultSource,
			})
		}
	}
	return assets
}

func route53Targets(record r53types.ResourceRecordSet) []string {
	if record.AliasTarget != nil {
		target := normalizeTarget(stringValue(record.AliasTarget.DNSName))
		if target != "" {
			return []string{target}
		}
		return nil
	}
	targets := make([]string, 0, len(record.ResourceRecords))
	for _, value := range record.ResourceRecords {
		target := normalizeTarget(stringValue(value.Value))
		if target != "" {
			targets = append(targets, target)
		}
	}
	sort.Strings(targets)
	return targets
}

func discoverCloudFront(ctx context.Context, accountID string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := cloudfront.NewFromConfig(cfg)
	paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	var assets []Asset
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cloudfront list distributions: %w", err)
		}
		if page.DistributionList == nil {
			continue
		}
		for _, dist := range page.DistributionList.Items {
			target := normalizeTarget(stringValue(dist.DomainName))
			if !isAllowedTarget(target, include, exclude) {
				continue
			}
			assets = append(assets, Asset{
				AccountID:  accountID,
				Service:    "cloudfront",
				AssetType:  "distribution",
				ResourceID: stringValue(dist.Id),
				Name:       stringValue(dist.Comment),
				Target:     target,
				Public:     true,
				Source:     defaultSource,
			})
		}
	}
	return assets, nil
}

func discoverS3Websites(ctx context.Context, accountID string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := s3.NewFromConfig(cfg)
	output, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("s3 list buckets: %w", err)
	}
	var assets []Asset
	regionalClients := map[string]*s3.Client{
		cfg.Region: client,
	}
	for _, bucket := range output.Buckets {
		name := strings.TrimSpace(stringValue(bucket.Name))
		if name == "" {
			continue
		}
		region, err := bucketRegion(ctx, client, name)
		if err != nil {
			return nil, err
		}
		regionalClient := regionalClients[region]
		if regionalClient == nil {
			regionalCfg := cfg.Copy()
			regionalCfg.Region = region
			regionalClient = s3.NewFromConfig(regionalCfg)
			regionalClients[region] = regionalClient
		}
		if _, err := regionalClient.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{Bucket: stringPtr(name)}); err != nil {
			if isBucketWebsiteMissing(err) {
				continue
			}
			return nil, fmt.Errorf("s3 get bucket website %s: %w", name, err)
		}
		target := normalizeTarget(s3WebsiteEndpoint(name, region))
		if !isAllowedTarget(target, include, exclude) {
			continue
		}
		assets = append(assets, Asset{
			AccountID:  accountID,
			Region:     region,
			Service:    "s3",
			AssetType:  "website_bucket",
			ResourceID: name,
			Name:       name,
			Target:     target,
			Public:     true,
			Source:     defaultSource,
		})
	}
	return assets, nil
}

func bucketRegion(ctx context.Context, client *s3.Client, bucket string) (string, error) {
	output, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: stringPtr(bucket)})
	if err != nil {
		return "", fmt.Errorf("s3 get bucket location %s: %w", bucket, err)
	}
	region := string(output.LocationConstraint)
	if region == "" {
		return "us-east-1", nil
	}
	if region == "EU" {
		return "eu-west-1", nil
	}
	return region, nil
}

func discoverRegion(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	discoverers := []func(context.Context, string, string, aws.Config, []string, []string) ([]Asset, error){
		discoverEC2,
		discoverELB,
		discoverELBV2,
		discoverAPIGateway,
		discoverAPIGatewayV2,
		discoverLightsail,
		discoverEKS,
		discoverLambdaURLs,
	}

	assets := make([]Asset, 0, 32)
	for _, discover := range discoverers {
		serviceAssets, err := discover(ctx, accountID, region, cfg, include, exclude)
		if err != nil {
			return nil, err
		}
		assets = append(assets, serviceAssets...)
	}
	return assets, nil
}

func discoverEC2(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := ec2.NewFromConfig(cfg)
	var assets []Asset

	addresses, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("ec2 describe addresses for %s: %w", region, err)
	}
	for _, address := range addresses.Addresses {
		target := normalizeTarget(stringValue(address.PublicIp))
		if !isAllowedTarget(target, include, exclude) {
			continue
		}
		assets = append(assets, Asset{
			AccountID:  accountID,
			Region:     region,
			Service:    "ec2",
			AssetType:  "elastic_ip",
			ResourceID: stringValue(address.AllocationId),
			Name:       stringValue(address.PublicIpv4Pool),
			Target:     target,
			Public:     true,
			Source:     defaultSource,
		})
	}

	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ec2 describe instances for %s: %w", region, err)
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				target := normalizeTarget(stringValue(instance.PublicDnsName))
				if target == "" {
					target = normalizeTarget(stringValue(instance.PublicIpAddress))
				}
				if !isAllowedTarget(target, include, exclude) {
					continue
				}
				assets = append(assets, Asset{
					AccountID:  accountID,
					Region:     region,
					Service:    "ec2",
					AssetType:  "instance",
					ResourceID: stringValue(instance.InstanceId),
					Name:       firstInstanceName(instance.Tags),
					Target:     target,
					Public:     true,
					Source:     defaultSource,
				})
			}
		}
	}

	return assets, nil
}

func discoverELB(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := elasticloadbalancing.NewFromConfig(cfg)
	paginator := elasticloadbalancing.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancing.DescribeLoadBalancersInput{})
	var assets []Asset
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("elb describe load balancers for %s: %w", region, err)
		}
		for _, lb := range page.LoadBalancerDescriptions {
			if !strings.EqualFold(stringValue(lb.Scheme), "internet-facing") {
				continue
			}
			target := normalizeTarget(stringValue(lb.DNSName))
			if !isAllowedTarget(target, include, exclude) {
				continue
			}
			assets = append(assets, Asset{
				AccountID:  accountID,
				Region:     region,
				Service:    "elb",
				AssetType:  "load_balancer",
				ResourceID: stringValue(lb.LoadBalancerName),
				Name:       stringValue(lb.LoadBalancerName),
				Target:     target,
				Public:     true,
				Source:     defaultSource,
			})
		}
	}
	return assets, nil
}

func discoverELBV2(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := elasticloadbalancingv2.NewFromConfig(cfg)
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	var assets []Asset
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("elbv2 describe load balancers for %s: %w", region, err)
		}
		for _, lb := range page.LoadBalancers {
			if lb.Scheme != elbv2types.LoadBalancerSchemeEnumInternetFacing {
				continue
			}
			target := normalizeTarget(stringValue(lb.DNSName))
			if !isAllowedTarget(target, include, exclude) {
				continue
			}
			assets = append(assets, Asset{
				AccountID:  accountID,
				Region:     region,
				Service:    "elbv2",
				AssetType:  "load_balancer",
				ResourceID: stringValue(lb.LoadBalancerArn),
				Name:       stringValue(lb.LoadBalancerName),
				Target:     target,
				Public:     true,
				Source:     defaultSource,
			})
		}
	}
	return assets, nil
}

func discoverAPIGateway(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := apigateway.NewFromConfig(cfg)
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})
	var assets []Asset
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("apigateway get rest apis for %s: %w", region, err)
		}
		for _, api := range page.Items {
			if restAPIIsPrivate(api) {
				continue
			}
			target := normalizeTarget(fmt.Sprintf("%s.execute-api.%s.amazonaws.com", stringValue(api.Id), region))
			if !isAllowedTarget(target, include, exclude) {
				continue
			}
			assets = append(assets, Asset{
				AccountID:  accountID,
				Region:     region,
				Service:    "apigateway",
				AssetType:  "rest_api",
				ResourceID: stringValue(api.Id),
				Name:       stringValue(api.Name),
				Target:     target,
				Public:     true,
				Source:     defaultSource,
			})
		}
	}
	return assets, nil
}

func discoverAPIGatewayV2(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := apigatewayv2.NewFromConfig(cfg)
	var assets []Asset
	var nextToken *string
	for {
		page, err := client.GetApis(ctx, &apigatewayv2.GetApisInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("apigatewayv2 get apis for %s: %w", region, err)
		}
		for _, api := range page.Items {
			target := normalizeURLHost(stringValue(api.ApiEndpoint))
			if !isAllowedTarget(target, include, exclude) {
				continue
			}
			assets = append(assets, Asset{
				AccountID:  accountID,
				Region:     region,
				Service:    "apigatewayv2",
				AssetType:  "api",
				ResourceID: stringValue(api.ApiId),
				Name:       stringValue(api.Name),
				Target:     target,
				Public:     true,
				Source:     defaultSource,
			})
		}
		if strings.TrimSpace(stringValue(page.NextToken)) == "" {
			break
		}
		nextToken = page.NextToken
	}
	return assets, nil
}

func discoverLightsail(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := lightsail.NewFromConfig(cfg)
	var assets []Asset

	instances, err := client.GetInstances(ctx, &lightsail.GetInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("lightsail get instances for %s: %w", region, err)
	}
	for _, instance := range instances.Instances {
		target := normalizeTarget(stringValue(instance.PublicIpAddress))
		if !isAllowedTarget(target, include, exclude) {
			continue
		}
		assets = append(assets, Asset{
			AccountID:  accountID,
			Region:     region,
			Service:    "lightsail",
			AssetType:  "instance",
			ResourceID: stringValue(instance.Name),
			Name:       stringValue(instance.Name),
			Target:     target,
			Public:     true,
			Source:     defaultSource,
		})
	}

	loadBalancers, err := client.GetLoadBalancers(ctx, &lightsail.GetLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("lightsail get load balancers for %s: %w", region, err)
	}
	for _, lb := range loadBalancers.LoadBalancers {
		target := normalizeTarget(stringValue(lb.DnsName))
		if !isAllowedTarget(target, include, exclude) {
			continue
		}
		assets = append(assets, Asset{
			AccountID:  accountID,
			Region:     region,
			Service:    "lightsail",
			AssetType:  "load_balancer",
			ResourceID: stringValue(lb.Name),
			Name:       stringValue(lb.Name),
			Target:     target,
			Public:     true,
			Source:     defaultSource,
		})
	}

	return assets, nil
}

func discoverEKS(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := eks.NewFromConfig(cfg)
	var assets []Asset
	var nextToken *string
	for {
		clusters, err := client.ListClusters(ctx, &eks.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("eks list clusters for %s: %w", region, err)
		}
		for _, name := range clusters.Clusters {
			cluster, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
			if err != nil {
				return nil, fmt.Errorf("eks describe cluster %s for %s: %w", name, region, err)
			}
			if cluster.Cluster == nil || cluster.Cluster.ResourcesVpcConfig == nil || !cluster.Cluster.ResourcesVpcConfig.EndpointPublicAccess {
				continue
			}
			target := normalizeURLHost(stringValue(cluster.Cluster.Endpoint))
			if !isAllowedTarget(target, include, exclude) {
				continue
			}
			assets = append(assets, Asset{
				AccountID:  accountID,
				Region:     region,
				Service:    "eks",
				AssetType:  "cluster_endpoint",
				ResourceID: stringValue(cluster.Cluster.Arn),
				Name:       stringValue(cluster.Cluster.Name),
				Target:     target,
				Public:     true,
				Source:     defaultSource,
			})
		}
		if strings.TrimSpace(stringValue(clusters.NextToken)) == "" {
			break
		}
		nextToken = clusters.NextToken
	}
	return assets, nil
}

func discoverLambdaURLs(ctx context.Context, accountID, region string, cfg aws.Config, include, exclude []string) ([]Asset, error) {
	client := lambda.NewFromConfig(cfg)
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	var assets []Asset
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("lambda list functions for %s: %w", region, err)
		}
		for _, fn := range page.Functions {
			out, err := client.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{FunctionName: fn.FunctionName})
			if err != nil {
				var notFound *lambdatypes.ResourceNotFoundException
				if errors.As(err, &notFound) {
					continue
				}
				return nil, fmt.Errorf("lambda get function url config %s for %s: %w", stringValue(fn.FunctionName), region, err)
			}
			target := normalizeURLHost(stringValue(out.FunctionUrl))
			if !isAllowedTarget(target, include, exclude) {
				continue
			}
			assets = append(assets, Asset{
				AccountID:  accountID,
				Region:     region,
				Service:    "lambda",
				AssetType:  "function_url",
				ResourceID: stringValue(fn.FunctionArn),
				Name:       stringValue(fn.FunctionName),
				Target:     target,
				Public:     true,
				Source:     defaultSource,
			})
		}
	}
	return assets, nil
}

func Targets(assets []Asset) []string {
	seen := make(map[string]struct{}, len(assets))
	targets := make([]string, 0, len(assets))
	for _, asset := range assets {
		target := normalizeTarget(asset.Target)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

func BuildInventorySnapshot(now time.Time, assets []Asset, opts DiscoverOptions) InventorySnapshot {
	return InventorySnapshot{
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Source:        defaultSource,
		Accounts:      accountsFromAssets(assets),
		Regions:       regionsFromAssets(assets),
		RegionFilters: uniqueSortedValues(opts.Regions),
		Include:       uniqueSortedValues(opts.Include),
		Exclude:       uniqueSortedValues(opts.Exclude),
		AssetCount:    len(assets),
		Assets:        append([]Asset(nil), assets...),
	}
}

func DiffInventory(now time.Time, previous, current InventorySnapshot) InventoryDiff {
	prevByKey := make(map[string]Asset, len(previous.Assets))
	currByKey := make(map[string]Asset, len(current.Assets))

	for _, asset := range previous.Assets {
		prevByKey[assetChangeKey(asset)] = asset
	}
	for _, asset := range current.Assets {
		currByKey[assetChangeKey(asset)] = asset
	}

	diff := InventoryDiff{
		GeneratedAt:         now.UTC().Format(time.RFC3339),
		Source:              defaultSource,
		PreviousGeneratedAt: previous.GeneratedAt,
		CurrentGeneratedAt:  current.GeneratedAt,
	}

	for key, currentAsset := range currByKey {
		previousAsset, existed := prevByKey[key]
		if !existed {
			diff.Added = append(diff.Added, currentAsset)
			continue
		}
		if assetIdentity(previousAsset) != assetIdentity(currentAsset) ||
			previousAsset.Public != currentAsset.Public ||
			previousAsset.Source != currentAsset.Source {
			diff.Changed = append(diff.Changed, AssetChange{Before: previousAsset, After: currentAsset})
		}
	}

	for key, previousAsset := range prevByKey {
		if _, exists := currByKey[key]; !exists {
			diff.Removed = append(diff.Removed, previousAsset)
		}
	}

	sort.Slice(diff.Added, func(i, j int) bool { return assetKey(diff.Added[i]) < assetKey(diff.Added[j]) })
	sort.Slice(diff.Removed, func(i, j int) bool { return assetKey(diff.Removed[i]) < assetKey(diff.Removed[j]) })
	sort.Slice(diff.Changed, func(i, j int) bool {
		return assetChangeKey(diff.Changed[i].After) < assetChangeKey(diff.Changed[j].After)
	})

	diff.AddedCount = len(diff.Added)
	diff.RemovedCount = len(diff.Removed)
	diff.ChangedCount = len(diff.Changed)

	return diff
}

func TargetsFromDiff(diff InventoryDiff) []string {
	assets := append([]Asset(nil), diff.Added...)
	for _, change := range diff.Changed {
		assets = append(assets, change.After)
	}
	return Targets(assets)
}

func accountsFromAssets(assets []Asset) []string {
	values := make([]string, 0, len(assets))
	for _, asset := range assets {
		values = append(values, asset.AccountID)
	}
	return uniqueSortedValues(values)
}

func regionsFromAssets(assets []Asset) []string {
	values := make([]string, 0, len(assets))
	for _, asset := range assets {
		if asset.Region != "" {
			values = append(values, asset.Region)
		}
	}
	return uniqueSortedValues(values)
}

func dedupeAssets(assets []Asset) []Asset {
	seen := make(map[string]struct{}, len(assets))
	out := make([]Asset, 0, len(assets))
	for _, asset := range assets {
		key := assetIdentity(asset)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, asset)
	}
	return out
}

func assetKey(asset Asset) string {
	return strings.Join([]string{
		asset.AccountID,
		asset.Region,
		asset.Service,
		asset.AssetType,
		asset.ResourceID,
		asset.Target,
	}, "|")
}

func assetChangeKey(asset Asset) string {
	return strings.Join([]string{
		asset.AccountID,
		asset.Region,
		asset.Service,
		asset.AssetType,
		asset.ResourceID,
	}, "|")
}

func assetIdentity(asset Asset) string {
	return strings.Join([]string{
		assetChangeKey(asset),
		asset.Name,
		asset.Target,
		fmt.Sprintf("%t", asset.Public),
		asset.Source,
	}, "|")
}

func uniqueSortedValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizePatterns(values []string) []string {
	patterns := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeTarget(value)
		if value == "" {
			continue
		}
		patterns = append(patterns, value)
	}
	return patterns
}

func normalizeTarget(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func normalizeURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if host == "" {
		return ""
	}
	return normalizeTarget(host)
}

func isAllowedTarget(target string, include, exclude []string) bool {
	target = normalizeTarget(target)
	if target == "" || isValidationRecordName(target) {
		return false
	}
	if ip := net.ParseIP(target); ip != nil && !isPublicIP(ip) {
		return false
	}
	return matchesAny(target, include, true) && !matchesAny(target, exclude, false)
}

func isScannableRecordType(recordType string) bool {
	switch recordType {
	case "A", "AAAA", "CNAME":
		return true
	default:
		return false
	}
}

func isValidationRecordName(name string) bool {
	labels := strings.Split(normalizeTarget(name), ".")
	if len(labels) == 0 {
		return true
	}
	if labels[0] == "*" {
		return true
	}
	for _, label := range labels {
		if strings.HasPrefix(label, "_") {
			return true
		}
	}
	return false
}

func matchesAny(target string, patterns []string, emptyDefault bool) bool {
	if len(patterns) == 0 {
		return emptyDefault
	}
	for _, pattern := range patterns {
		if patternMatches(target, pattern) {
			return true
		}
	}
	return false
}

func patternMatches(target, pattern string) bool {
	if strings.ContainsAny(pattern, "*?[") {
		ok, err := path.Match(pattern, target)
		return err == nil && ok
	}
	return target == pattern || strings.HasSuffix(target, "."+pattern)
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

func firstInstanceName(tags []ec2types.Tag) string {
	for _, tag := range tags {
		if strings.EqualFold(stringValue(tag.Key), "name") {
			return stringValue(tag.Value)
		}
	}
	return ""
}

func restAPIIsPrivate(api apigwtypes.RestApi) bool {
	if api.EndpointConfiguration == nil {
		return false
	}
	if len(api.EndpointConfiguration.Types) == 0 {
		return false
	}
	for _, endpointType := range api.EndpointConfiguration.Types {
		if endpointType == apigwtypes.EndpointTypePrivate {
			return true
		}
	}
	return false
}

func s3WebsiteEndpoint(bucket, region string) string {
	return fmt.Sprintf("%s.s3-website-%s.amazonaws.com", bucket, region)
}

func isBucketWebsiteMissing(err error) bool {
	type apiError interface {
		ErrorCode() string
	}
	var typed apiError
	if errors.As(err, &typed) {
		return typed.ErrorCode() == "NoSuchWebsiteConfiguration"
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such website configuration")
}

func stringValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return strings.TrimSpace(*ptr)
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}
