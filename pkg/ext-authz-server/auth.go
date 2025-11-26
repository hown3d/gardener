package extauthzserver

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	envoycorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoytypev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/go-logr/logr"
	"google.golang.org/genproto/googleapis/rpc/code"
	googlestatus "google.golang.org/genproto/googleapis/rpc/status"
)

type server struct {
	log   logr.Logger
	store *store
}

var _ envoy_service_auth_v3.AuthorizationServer = &server{}

// New creates a new authorization server.
func New(log logr.Logger, dir fs.FS) (envoy_service_auth_v3.AuthorizationServer, error) {
	store, err := newStore(dir)
	if err != nil {
		return nil, fmt.Errorf("setting up store: %w", err)
	}
	return &server{
		log:   log,
		store: store,
	}, nil
}

// Check implements authorization's Check interface which performs authorization check based on the
// attributes associated with the incoming request.
func (s *server) Check(
	ctx context.Context,
	req *envoy_service_auth_v3.CheckRequest,
) (*envoy_service_auth_v3.CheckResponse, error) {
	if req.Attributes == nil || req.Attributes.Request == nil || req.Attributes.Request.Http == nil {
		return denyResponse("invalid request"), nil
	}
	http := req.Attributes.Request.Http
	auth := http.Headers["Authorization"]
	if auth == "" {
		return denyResponse("missing Authorization header"), nil
	}
	host := req.Attributes.Request.Http.Host
	hostParts := strings.Split(host, ".")
	if len(hostParts) == 0 || host == "" {
		s.log.Info("[WARN] no Host header in request found, denying request")
		return denyResponse("missing host"), nil
	}

	err := s.store.IsValid(hostParts[0], []byte(auth))
	if err != nil {
		s.log.Error(err, "denied request ", "auth", auth)
		return denyResponse("invalid authorization"), nil
	}

	return &envoy_service_auth_v3.CheckResponse{
		Status: &googlestatus.Status{
			Code: int32(code.Code_OK),
		},
	}, nil
}

func denyResponse(message string) *envoy_service_auth_v3.CheckResponse {
	missingAuthResponse := &envoy_service_auth_v3.CheckResponse_DeniedResponse{
		DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
			Headers: []*envoycorev3.HeaderValueOption{
				{
					Header: &envoycorev3.HeaderValue{Key: "WWW-Authenticate", Value: "Basic realm=\"User Visible Realm\""},
				},
			},
			Status: &envoytypev3.HttpStatus{Code: envoytypev3.StatusCode_Unauthorized},
		},
	}
	return &envoy_service_auth_v3.CheckResponse{
		Status: &googlestatus.Status{
			Code:    int32(code.Code_PERMISSION_DENIED),
			Message: message,
		},
		HttpResponse: missingAuthResponse,
	}
}
