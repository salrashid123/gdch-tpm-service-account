package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"net/http"

	"log"
	"net/http/httputil"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
)

type contextKey string

const contextEventKey contextKey = "event"

// https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2.1
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type,omitempty"`
	ExpiresIn       int64  `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// support standard TokenTypes
const (
	AccessToken  string = "urn:ietf:params:oauth:token-type:access_token"
	RefreshToken string = "urn:ietf:params:oauth:token-type:refresh_token"
	IDToken      string = "urn:ietf:params:oauth:token-type:id_token"
	SAML1        string = "urn:ietf:params:oauth:token-type:saml1"
	SAML2        string = "urn:ietf:params:oauth:token-type:saml2"
	JWT          string = "urn:ietf:params:oauth:token-type:jwt"
	GCDH         string = "urn:k8s:params:oauth:token-type:serviceaccount"
)

const ()

var (
	httpport = flag.String("httpport", ":8081", "httpport")

	// support standard TokenTypes
	tokenTypes = []string{GCDH}

	debug      = flag.Bool("debug", false, "debug input requests")
	skipTLS    = flag.Bool("skipTLS", false, "do not use TLS")
	usemTLS    = flag.Bool("usemTLS", false, "Use mTLS")
	rootCAmTLS = flag.String("rootCAmTLS", "certs/root-ca.crt", "rootCA to validate client certs ")
	serverCert = flag.String("serverCert", "certs/sts.crt", "Server mtls certificate")
	serverKey  = flag.String("serverKey", "certs/sts.key", "Server mtls key")

	workloadPublicKey = flag.String("workloadPublicKey", "certs/public_key.pem", "Public key to verify the JWT")

	workloadVerifyPublic *ecdsa.PublicKey

	version           = flag.Bool("version", false, "print version")
	Commit, Tag, Date string
)

type stsRequest struct {
	GrantType        string `json:"grant_type"`
	Resource         string `json:"resource,omitempty"`
	Audience         string `json:"audience,omitempty"`
	Scope            string `json:"scope,omitempty"`
	RequestTokenType string `json:"requested_token_type,omitempty"`
	SubjectToken     string `json:"subject_token"`
	SubjectTokenType string `json:"subject_token_type"`
	ActorToken       string `json:"actor_token,omitempty"`
	ActorTokenType   string `json:"actor_token_type,omitempty"`
}

func isValidTokenType(str string) bool {
	for _, a := range tokenTypes {
		if a == str {
			return true
		}
	}
	return false
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if *debug {
			requestDump, err := httputil.DumpRequest(r, true)
			if err != nil {
				fmt.Printf("Error Reading Request: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			fmt.Printf("Request: %s\n", string(requestDump))
		}
		event := &stsRequest{}

		contentType := r.Header.Get("Content-type")

		switch {
		case contentType == "application/json":
			err := json.NewDecoder(r.Body).Decode(event)
			if err != nil {
				fmt.Printf("Could Not parse application/json payload: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		case contentType == "application/x-www-form-urlencoded":
			err := r.ParseForm()
			if err != nil {
				fmt.Printf("Could not parse application/x-www-form-urlencode Form: %v", err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			v := r.Form

			event = &stsRequest{
				GrantType:        v.Get("grant_type"),
				Resource:         v.Get("resource"),
				Audience:         v.Get("audience"),
				Scope:            v.Get("scope"),
				SubjectToken:     v.Get("subject_token"),
				SubjectTokenType: v.Get("subject_token_type"),
				ActorToken:       v.Get("actor_token"),
				ActorTokenType:   v.Get("actor_token_type"),
			}
		default:
			fmt.Printf("Invalid Content Type [%s]", contentType)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func tokenhandlerpost(w http.ResponseWriter, r *http.Request) {

	val := r.Context().Value(contextKey("event")).(stsRequest)

	if val.GrantType == "" || val.SubjectToken == "" || val.SubjectTokenType == "" {
		fmt.Printf("Invalid Request Payload Headers: \n %v\n", val)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if !isValidTokenType(val.SubjectTokenType) {
		fmt.Printf("Invalid subject_token_type: %s", val.SubjectTokenType)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if val.ActorTokenType != "" && !isValidTokenType(val.ActorTokenType) {
		log.Printf("Invalid actor_token_type: %s", val.ActorTokenType)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	verifiedToken, err := verifyToken(val.SubjectToken, workloadVerifyPublic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", fmt.Sprintf("Could not validate token %v", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	sub, err := verifiedToken.Claims.GetSubject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", fmt.Sprintf("Could not get subject from subjectToken %v", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	fmt.Printf("JWT Subject: %s\n", sub)

	aud, err := verifiedToken.Claims.GetAudience()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", fmt.Sprintf("Could not get audience from subjectToken %v", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	fmt.Printf("JWT Audience: %s\n", aud)

	iss, err := verifiedToken.Claims.GetIssuer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", fmt.Sprintf("Could not get issuer from subjectToken %v", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	fmt.Printf("JWT Issuer: %s\n", iss)

	fmt.Printf("Verified: %t\n", verifiedToken.Valid)
	fmt.Println()

	// gcpts, err := google.FindDefaultCredentials(context.Background())
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "%s", fmt.Sprintf("Could not get adc google token %v", err))
	// 	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	// 	return
	// }

	// tok, err := gcpts.TokenSource.Token()
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "%s", fmt.Sprintf("Could not get adc google tokensource Token %v", err))
	// 	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	// 	return
	// }

	tok := &oauth2.Token{
		AccessToken: "fake_access_token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	p := &TokenResponse{
		AccessToken:     tok.AccessToken,
		IssuedTokenType: AccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       tok.ExpiresIn,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")

	err = json.NewEncoder(w).Encode(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", fmt.Sprintf("Could not marshall JSON to output %v", err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
}

func main() {
	flag.Parse()

	router := mux.NewRouter()
	router.Path("/authenticate").Methods(http.MethodPost).HandlerFunc(tokenhandlerpost)

	var err error

	vbytes, err := os.ReadFile(*workloadPublicKey)
	if err != nil {
		log.Fatalf("Error reading workloadIdentity Public Key %s\n", err.Error())
	}
	workloadVerifyPublic, err = loadPublicKey(vbytes)
	server := &http.Server{
		Addr:    *httpport,
		Handler: eventsMiddleware(router),
	}

	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	if *skipTLS {

		err = server.ListenAndServe()
	} else {
		tlsConfig := &tls.Config{}

		if *usemTLS {
			clientCaCert, err := os.ReadFile(*rootCAmTLS)
			if err != nil {
				fmt.Printf("error reading rootCAmTLS %v\n", err)
				return
			}

			clientCaCertPool := x509.NewCertPool()
			clientCaCertPool.AppendCertsFromPEM(clientCaCert)
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = clientCaCertPool
			server.TLSConfig = tlsConfig
		}
		err = server.ListenAndServeTLS(*serverCert, *serverKey)
	}

	fmt.Printf("Unable to start Server %v", err)

}

func loadPublicKey(pemData []byte) (*ecdsa.PublicKey, error) {
	return jwt.ParseECPublicKeyFromPEM(pemData)
}

func verifyToken(tokenString string, publicKey *ecdsa.PublicKey) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}
	return token, nil
}
