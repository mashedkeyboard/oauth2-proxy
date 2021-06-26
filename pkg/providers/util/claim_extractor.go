package util

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/spf13/cast"
)

type ClaimExtractor interface {
	GetClaim(claim string) (interface{}, bool, error)
	GetClaimInto(claim string, dst interface{}) (bool, error)
}

func NewClaimExtractor(ctx context.Context, idToken *oidc.IDToken, profileURL *url.URL, profileRequestHeaders map[string][]string) (ClaimExtractor, error) {
	extractor := &claimExtractor{
		ctx:            ctx,
		profileURL:     profileURL,
		requestHeaders: profileRequestHeaders,
		tokenClaims:    make(map[string]interface{}),
	}

	if err := idToken.Claims(&extractor.tokenClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from ID Token: %v", err)
	}

	return extractor, nil
}

type claimExtractor struct {
	profileURL     *url.URL
	ctx            context.Context
	requestHeaders map[string][]string
	tokenClaims    map[string]interface{}
	profileClaims  map[string]interface{}
}

func (c *claimExtractor) GetClaim(claim string) (interface{}, bool, error) {
	if claim == "" {
		return nil, false, nil
	}

	if value, exists := c.tokenClaims[claim]; exists {
		return value, true, nil
	}

	if c.profileClaims == nil {
		profileClaims, err := c.getProfileClaims()
		if err != nil {
			return nil, false, fmt.Errorf("failed to fetch claims from profile URL: %v", err)
		}

		c.profileClaims = profileClaims
	}

	if value, exists := c.profileClaims[claim]; exists {
		return value, true, nil
	}

	return nil, false, nil
}

func (c *claimExtractor) getProfileClaims() (map[string]interface{}, error) {
	var claims map[string]interface{}

	if c.profileURL == nil || c.requestHeaders == nil {
		// When no profileURL is set, we return a non-empty map so that
		// we don't attempt to populate the profile claims again.
		// If there are no headers, the request would be unauthorized so we also skip
		// in this case too.
		return make(map[string]interface{}), nil
	}

	if err := requests.New(c.profileURL.String()).
		WithContext(c.ctx).
		WithHeaders(c.requestHeaders).
		Do().
		UnmarshalInto(&claims); err != nil {
		return nil, fmt.Errorf("error making request to profile URL: %v", err)
	}

	return claims, nil
}

func (c *claimExtractor) GetClaimInto(claim string, dst interface{}) (bool, error) {
	value, exists, err := c.GetClaim(claim)
	if err != nil {
		return false, fmt.Errorf("could not get claim %q: %v", claim, err)
	}
	if !exists {
		return false, nil
	}
	if err := coerceClaim(value, dst); err != nil {
		return false, fmt.Errorf("could no coerce claim: %v", err)
	}

	return true, nil
}

func coerceClaim(value, dst interface{}) error {
	switch d := dst.(type) {
	case *string:
		str, err := toString(value)
		if err != nil {
			return fmt.Errorf("could not convert value to string: %v", err)
		}
		*d = str
	case *[]string:
		strSlice, err := toStringSlice(value)
		if err != nil {
			return fmt.Errorf("could not convert value to string slice: %v", err)
		}
		*d = strSlice
	case *bool:
		*d = cast.ToBool(value)
	default:
		return fmt.Errorf("unknown type for destination: %T", dst)
	}
	return nil
}

func toStringSlice(value interface{}) ([]string, error) {
	var sliceValues []interface{}
	switch v := value.(type) {
	case []interface{}:
		sliceValues = v
	case interface{}:
		sliceValues = []interface{}{v}
	default:
		sliceValues = cast.ToSlice(value)
	}

	out := []string{}
	for _, v := range sliceValues {
		str, err := toString(v)
		if err != nil {
			return nil, fmt.Errorf("could not convert slice entry to string %v: %v", v, err)
		}
		out = append(out, str)
	}
	return out, nil
}

// formatGroup coerces an OIDC groups claim into a string
// If it is non-string, marshal it into JSON.
func toString(value interface{}) (string, error) {
	if str, err := cast.ToStringE(value); err == nil {
		return str, nil
	}

	jsonStr, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(jsonStr), nil
}
