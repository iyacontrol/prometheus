package hw

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	hwconfig "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	ecsv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	hwmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	"github.com/pkg/errors"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/refresh"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/util/strutil"
)

const (
	ecsLabel              = model.MetaLabelPrefix + "ecs_"
	ecsLabelInstanceID    = ecsLabel + "instance_id"
	ecsLabelInstanceName  = ecsLabel + "instance_name"
	ecsLabelInstanceState = ecsLabel + "instance_state"
	ecsLabelInstanceType  = ecsLabel + "instance_type"
	ecsLabelPrivateIP     = ecsLabel + "private_ip"
	ecsLabelTag           = ecsLabel + "tag_"
)

// DefaultSDConfig is the default EC2 SD configuration.
var DefaultSDConfig = SDConfig{
	Port:            80,
	RefreshInterval: model.Duration(60 * time.Second),
	SizePerFetch:    500,
}

func init() {
	discovery.RegisterConfig(&SDConfig{})
}

// SDConfig is the configuration for ECS based service discovery.
type SDConfig struct {
	Region          string         `yaml:"region"`
	Endpoint        string         `yaml:"endpoint"`
	ProjectID       string         `yaml:"project_id"`
	AccessKey       string         `yaml:"access_key,omitempty"`
	SecretKey       string         `yaml:"secret_key,omitempty"`
	RefreshInterval model.Duration `yaml:"refresh_interval,omitempty"`
	Port            int            `yaml:"port"`
	SizePerFetch    int32          `yaml:"size_per_fetch"`
}

// Name returns the name of the Config.
func (*SDConfig) Name() string { return "hw" }

// NewDiscoverer returns a Discoverer for the Config.
func (c *SDConfig) NewDiscoverer(opts discovery.DiscovererOptions) (discovery.Discoverer, error) {
	return NewDiscovery(c, opts.Logger), nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *SDConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultSDConfig
	type plain SDConfig
	err := unmarshal((*plain)(c))
	if err != nil {
		return err
	}
	return nil
}

// Discovery periodically performs ECS-SD requests. It implements
// the Discoverer interface.
type Discovery struct {
	*refresh.Discovery
	hw           *basic.Credentials
	region       string
	endpoint     string
	sizePerFetch int32
	interval     time.Duration
	port         int
}

// NewDiscovery returns a new EC2Discovery which periodically refreshes its targets.
func NewDiscovery(conf *SDConfig, logger log.Logger) *Discovery {
	creds := basic.NewCredentialsBuilder().
		WithAk(conf.AccessKey).
		WithSk(conf.SecretKey).
		WithProjectId(conf.ProjectID).
		Build()

	if logger == nil {
		logger = log.NewNopLogger()
	}

	d := &Discovery{
		hw:           &creds,
		endpoint:     conf.Endpoint,
		region:       conf.Region,
		interval:     time.Duration(conf.RefreshInterval),
		port:         conf.Port,
		sizePerFetch: conf.SizePerFetch,
	}
	d.Discovery = refresh.NewDiscovery(
		logger,
		"hw",
		time.Duration(conf.RefreshInterval),
		d.refresh,
	)
	return d
}

func (d *Discovery) refresh(ctx context.Context) ([]*targetgroup.Group, error) {
	client := ecsv2.NewEcsClient(
		ecsv2.EcsClientBuilder().
			WithEndpoint(d.endpoint).
			WithCredential(*d.hw).
			WithHttpConfig(hwconfig.DefaultHttpConfig()).
			Build())

	tg := &targetgroup.Group{
		Source: d.region,
	}

	var servers []hwmodel.ServerDetail

	request := &hwmodel.ListServersDetailsRequest{
		Limit: &d.sizePerFetch,
	}

	resp, err := client.ListServersDetails(request)
	if err != nil {
		return nil, errors.Wrap(err, "could not describe instances")
	}

	servers = append(servers, *resp.Servers...)

	// fetch others
	// if tryNum == -1, then all the servers has been fetched
	var tryNum int32 = 0

	if *resp.Count%d.sizePerFetch == 0 {
		tryNum = *resp.Count/d.sizePerFetch - 1
	} else {
		tryNum = *resp.Count / d.sizePerFetch
	}

	var i int32 = 0
	for ; i < tryNum; i++ {
		var offset int32 = i + 2
		request.Offset = &offset

		resp, err := client.ListServersDetails(request)
		if err != nil {

		}

		servers = append(servers, *resp.Servers...)

	}

	for _, server := range servers {
		var ip string
		for _, addresses := range server.Addresses {
			for _, address := range addresses {
				if address.Version == "4" {
					ip = address.Addr
				}
			}
		}
		if ip == "" {
			continue
		}

		labels := model.LabelSet{
			ecsLabelPrivateIP: model.LabelValue(ip),
		}
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", d.port))
		labels[model.AddressLabel] = model.LabelValue(addr)

		labels[ecsLabelInstanceID] = model.LabelValue(server.Id)
		labels[ecsLabelInstanceName] = model.LabelValue(server.Name)
		labels[ecsLabelInstanceState] = model.LabelValue(server.Status)
		labels[ecsLabelInstanceType] = model.LabelValue(server.Flavor.Id)

		for _, tag := range *server.Tags {
			kv := strings.Split(tag, "=")
			if len(kv) != 2 {
				continue
			}

			name := strutil.SanitizeLabelName(kv[0])
			labels[ecsLabelTag+model.LabelName(name)] = model.LabelValue(kv[1])
		}
		tg.Targets = append(tg.Targets, labels)

	}

	return []*targetgroup.Group{tg}, nil
}
