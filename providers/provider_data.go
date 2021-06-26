package providers

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/util"
	"golang.org/x/oauth2"
)

const (
	OIDCEmailClaim  = "email"
	OIDCGroupsClaim = "groups"
)

// ProviderData contains information required to configure all implementations
// of OAuth2 providers
type ProviderData struct {
	ProviderName      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	// Auth request params & related, see
	//https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.1.1.1
	AcrValues        string
	ApprovalPrompt   string // NOTE: Renamed to "prompt" in OAuth2
	ClientID         string
	ClientSecret     string
	ClientSecretFile string
	Scope            string
	Prompt           string

	// Common OIDC options for any OIDC-based providers to consume
	AllowUnverifiedEmail bool
	EmailClaim           string
	GroupsClaim          string
	Verifier             *oidc.IDTokenVerifier

	// Universal Group authorization data structure
	// any provider can set to consume
	AllowedGroups map[string]struct{}

	getAuthorizationHeaderFunc func(string) http.Header
}

// Data returns the ProviderData
func (p *ProviderData) Data() *ProviderData { return p }

func (p *ProviderData) GetClientSecret() (clientSecret string, err error) {
	if p.ClientSecret != "" || p.ClientSecretFile == "" {
		return p.ClientSecret, nil
	}

	// Getting ClientSecret can fail in runtime so we need to report it without returning the file name to the user
	fileClientSecret, err := ioutil.ReadFile(p.ClientSecretFile)
	if err != nil {
		logger.Errorf("error reading client secret file %s: %s", p.ClientSecretFile, err)
		return "", errors.New("could not read client secret file")
	}
	return string(fileClientSecret), nil
}

// SetAllowedGroups organizes a group list into the AllowedGroups map
// to be consumed by Authorize implementations
func (p *ProviderData) SetAllowedGroups(groups []string) {
	p.AllowedGroups = make(map[string]struct{}, len(groups))
	for _, group := range groups {
		p.AllowedGroups[group] = struct{}{}
	}
}

type providerDefaults struct {
	name        string
	loginURL    *url.URL
	redeemURL   *url.URL
	profileURL  *url.URL
	validateURL *url.URL
	scope       string
}

func (p *ProviderData) setProviderDefaults(defaults providerDefaults) {
	p.ProviderName = defaults.name
	p.LoginURL = defaultURL(p.LoginURL, defaults.loginURL)
	p.RedeemURL = defaultURL(p.RedeemURL, defaults.redeemURL)
	p.ProfileURL = defaultURL(p.ProfileURL, defaults.profileURL)
	p.ValidateURL = defaultURL(p.ValidateURL, defaults.validateURL)

	if p.Scope == "" {
		p.Scope = defaults.scope
	}
}

// defaultURL will set return a default value if the given value is not set.
func defaultURL(u *url.URL, d *url.URL) *url.URL {
	if u != nil && u.String() != "" {
		// The value is already set
		return u
	}

	// If the default is given, return that
	if d != nil {
		return d
	}
	return &url.URL{}
}

// ****************************************************************************
// These private OIDC helper methods are available to any providers that are
// OIDC compliant
// ****************************************************************************

// OIDCClaims is a struct to unmarshal the OIDC claims from an ID Token payload
type OIDCClaims struct {
	Subject  string   `json:"sub"`
	Email    string   `json:"-"`
	Groups   []string `json:"-"`
	Verified *bool    `json:"email_verified"`
	Nonce    string   `json:"nonce"`

	raw map[string]interface{}
}

func (p *ProviderData) verifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken := getIDToken(token)
	if strings.TrimSpace(rawIDToken) == "" {
		return nil, ErrMissingIDToken
	}
	if p.Verifier == nil {
		return nil, ErrMissingOIDCVerifier
	}
	return p.Verifier.Verify(ctx, rawIDToken)
}

// buildSessionFromClaims uses IDToken claims to populate a fresh SessionState
// with non-Token related fields.
func (p *ProviderData) buildSessionFromClaims(idToken *oidc.IDToken, accessToken string) (*sessions.SessionState, error) {
	ss := &sessions.SessionState{}

	if idToken == nil {
		return ss, nil
	}

	extractor, err := p.getClaimExtractor(idToken, accessToken)
	if err != nil {
		return nil, err
	}

	for claim, dst := range map[string]interface{}{
		"sub":         &ss.User,
		p.EmailClaim:  &ss.Email,
		p.GroupsClaim: &ss.Groups,
		// TODO (@NickMeves) Deprecate for dynamic claim to session mapping
		"preferred_username": &ss.PreferredUsername,
	} {
		if _, err := extractor.GetClaimInto(claim, dst); err != nil {
			return nil, err
		}
	}

	// `email_verified` must be present and explicitly set to `false` to be
	// considered unverified.
	verifyEmail := (p.EmailClaim == OIDCEmailClaim) && !p.AllowUnverifiedEmail

	var verified bool
	exists, err := extractor.GetClaimInto("email_verified", &verified)
	if err != nil {
		return nil, err
	}

	if verifyEmail && exists && !verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", ss.Email)
	}

	return ss, nil
}

func (p *ProviderData) getClaimExtractor(idToken *oidc.IDToken, accessToken string) (util.ClaimExtractor, error) {
	extractor, err := util.NewClaimExtractor(context.TODO(), idToken, p.ProfileURL, p.getAuthorizationHeader(accessToken))
	if err != nil {
		return nil, fmt.Errorf("could not initialise claim extractor: %v", err)
	}

	return extractor, nil
}

// checkNonce compares the session's nonce with the IDToken's nonce claim
func (p *ProviderData) checkNonce(s *sessions.SessionState, idToken *oidc.IDToken) error {
	extractor, err := p.getClaimExtractor(idToken, "")
	if err != nil {
		return fmt.Errorf("id_token claims extraction failed: %v", err)
	}
	var nonce string
	if _, err := extractor.GetClaimInto("nonce", &nonce); err != nil {
		return fmt.Errorf("could not extract nonce from ID Token: %v", err)
	}

	if !s.CheckNonce(nonce) {
		return errors.New("id_token nonce claim does not match the session nonce")
	}
	return nil
}

func (p *ProviderData) getAuthorizationHeader(accessToken string) http.Header {
	if p.getAuthorizationHeaderFunc != nil && accessToken != "" {
		return p.getAuthorizationHeaderFunc(accessToken)
	}
	return nil
}
