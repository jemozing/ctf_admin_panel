// Package docker contains the bounded Docker Engine and Compose adapters.
package docker

import (
	"context"
	"fmt"
	"sort"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
)

type Engine struct{ Client *client.Client }

func New(c config.Config) (*Engine, error) {
	api, err := client.New(client.WithHost(c.DockerHost))
	if err != nil {
		return nil, err
	}
	return &Engine{Client: api}, nil
}

func (e *Engine) Close() error { return e.Client.Close() }

type Container struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Project   string   `json:"project"`
	Component string   `json:"component"`
	ImageID   string   `json:"image_id"`
	State     string   `json:"state"`
	Health    string   `json:"health"`
	Mounts    []Mount  `json:"mounts"`
	Ports     []string `json:"ports"`
	// runtime is executor-only evidence. A public DTO cannot authorize a runtime.
	runtime *runtimeInspection
}

type Mount struct {
	Type     string `json:"type"`
	Source   string `json:"source,omitempty"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

func (e *Engine) Inventory(ctx context.Context, project string) ([]Container, error) {
	opts := client.ContainerListOptions{All: true}
	if project != "" {
		opts.Filters = client.Filters{}.Add("label", "com.docker.compose.project="+project)
	}
	res, err := e.Client.ContainerList(ctx, opts)
	if err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(res.Items))
	networks := map[string]network.Inspect{}
	volumes := map[string]volume.Volume{}
	for _, item := range res.Items {
		r, err := e.Client.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
		if err != nil {
			return nil, err
		}
		info := r.Container
		image, err := e.Client.ImageInspect(ctx, info.Image)
		if err != nil {
			return nil, fmt.Errorf("runtime image inspection unavailable")
		}
		c := Container{ID: item.ID, Name: info.Name, ImageID: info.Image, Project: item.Labels["com.docker.compose.project"], Component: item.Labels["com.docker.compose.service"], Health: "not_configured", Mounts: []Mount{}, Ports: []string{}}
		c.runtime = &runtimeInspection{container: info, image: image.InspectResponse, networks: map[string]network.Inspect{}, volumes: map[string]volume.Volume{}}
		if info.State != nil {
			c.State = string(info.State.Status)
			if info.State.Health != nil {
				c.Health = string(info.State.Health.Status)
			}
		}
		for _, m := range info.Mounts {
			source := m.Source
			if m.Type == "volume" {
				source = m.Name
				metadata, ok := volumes[m.Name]
				if !ok {
					inspected, err := e.Client.VolumeInspect(ctx, m.Name, client.VolumeInspectOptions{})
					if err != nil {
						return nil, fmt.Errorf("runtime volume inspection unavailable")
					}
					metadata = inspected.Volume
					volumes[m.Name] = metadata
				}
				c.runtime.volumes[m.Name] = metadata
			}
			c.Mounts = append(c.Mounts, Mount{Type: string(m.Type), Source: source, Target: m.Destination, ReadOnly: !m.RW})
		}
		if info.NetworkSettings != nil {
			for name, endpoint := range info.NetworkSettings.Networks {
				key := name
				if endpoint != nil && endpoint.NetworkID != "" {
					key = endpoint.NetworkID
				}
				metadata, ok := networks[key]
				if !ok {
					inspected, err := e.Client.NetworkInspect(ctx, key, client.NetworkInspectOptions{})
					if err != nil {
						return nil, fmt.Errorf("runtime network inspection unavailable")
					}
					metadata = inspected.Network
					networks[key] = metadata
				}
				c.runtime.networks[name] = metadata
			}
			for port, bindings := range info.NetworkSettings.Ports {
				for _, binding := range bindings {
					c.Ports = append(c.Ports, fmt.Sprintf("%s:%s->%s", binding.HostIP, binding.HostPort, port))
				}
			}
		}
		sort.Strings(c.Ports)
		sort.Slice(c.Mounts, func(i, j int) bool { return c.Mounts[i].Target < c.Mounts[j].Target })
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
