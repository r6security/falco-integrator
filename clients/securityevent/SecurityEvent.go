package securityevent

import (
	"context"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	"k8s.io/client-go/rest"
)

type SecurityEventInterface interface {
	Create(ctx context.Context, obj *amtdapi.SecurityEvent) (*amtdapi.SecurityEvent, error)
}

type securityEventClient struct {
	client rest.Interface
}

func NewSecurityEventClient(client rest.Interface) SecurityEventInterface {
	return &securityEventClient{
		client: client,
	}
}

func (c *securityEventClient) Create(ctx context.Context, obj *amtdapi.SecurityEvent) (*amtdapi.SecurityEvent, error) {
	result := &amtdapi.SecurityEvent{}
	err := c.client.
		Post().
		Resource("securityevents").
		Body(obj).
		Do(ctx).
		Into(result)
	return result, err
}
