// Creates creates GCP access tokens where the service account key
// is saved on a Trusted Platform Module (TPM).

package gdchtpm

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	jwt "github.com/golang-jwt/jwt/v5"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	salsts "github.com/salrashid123/sts/http"
	"golang.org/x/oauth2"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var ()

const (
	PARENT_PASS_VAR = "TPM_PARENT_AUTH"
	KEY_PASS_VAR    = "TPM_KEY_AUTH"
)

type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// ExpiresIn is the OAuth2 wire format "expires_in" field,
	// which specifies how many seconds later the token expires,
	// relative to an unknown time base approximately around "now".
	// It is the application's responsibility to populate
	// `Expiry` from `ExpiresIn` when required.
	ExpiresIn int64 `json:"expires_in,omitempty"`
}

type GDCHTPMConfig struct {
	TPMCloser        io.ReadWriteCloser // TPM Reqd closer
	PersistentHandle uint               // use if key is referenced as persistent handle
	KeyFileBytes     []byte             // use if key is referenced as PEM keyfile

	STSServerRootCA *x509.CertPool
	STSServerName   string
	STSJWTExpireIn  int

	ServiceAccountName string
	ProjectID          string
	TokenURI           string
	KeyID              string

	UseEKParent         ParentKeyType // set true if the parent is rsa_ek or ecc_ek
	Audience            string        // audience for the id_token
	ServiceAccountEmail string        // name of the service account

	SessionEncryptionName string // hex string "name" of the rsa_ek to use for session encryption
	Parentpass            string // password for the parent object
	Keypass               string // password for the key object
	Pcrs                  string // string form of the pcrs to use (formatted as pcr_bank:pcr_sha256Hex)

	Certificate *x509.Certificate //used for mtls workload federation
}

var ()

type ParentKeyType int

const (
	H2 ParentKeyType = iota
	RSA_EK
	ECC_EK
)

const (
	DEFAULT_STSJWTExpireIn = 5
)

func (d ParentKeyType) String() string {
	return [...]string{"h2", "rsa_ek", "ecc_ek"}[d]
}

func NewGDCHTPMCredential(cfg *GDCHTPMConfig) (t *Token, e error) {

	rwr := transport.FromReadWriter(cfg.TPMCloser)

	// first acquire the default RSA EK key to use for encrypted sessions.  You should
	// supply the SessionEncryptionName parameter (othewise getting the default rsa_ek manually isn't too secure anwyay...)
	var encryptionSessionHandle tpm2.TPMHandle
	createEKRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
		},
		InPublic: tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		return &Token{}, fmt.Errorf("gdch-tpm-credential: can't acquire acquire ek %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()
	encryptionSessionHandle = createEKRsp.ObjectHandle

	ekoutPub, err := createEKRsp.OutPublic.Contents()
	if err != nil {
		return &Token{}, fmt.Errorf("gdch-tpm-credential: error getting encryption name %v", err)
	}

	// if the encryptionName was specified as argument, compare it
	if cfg.SessionEncryptionName != "" {
		if cfg.SessionEncryptionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return &Token{}, fmt.Errorf("gdch-tpm-credential: session encryption names do not match expected [%s] got [%s]", cfg.SessionEncryptionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
	}

	// this is the service account key to use for getting a token
	var svcAccountKey tpm2.TPMHandle

	parentPasswordAuth := getEnv(PARENT_PASS_VAR, "", cfg.Parentpass)
	keyPasswordAuth := getEnv(KEY_PASS_VAR, "", cfg.Keypass)

	var primaryKey *tpm2.CreatePrimaryResponse
	var parentSession tpm2.Session
	var load_session_cleanup func() error
	// if a keyfile was specfified
	if cfg.KeyFileBytes != nil {

		key, err := keyfile.Decode(cfg.KeyFileBytes)
		if err != nil {
			return &Token{}, fmt.Errorf("gdch-tpm-credential: failed decoding key: %v", err)
		}

		// are we deailing with an rsa_ek or ecc_ek, if so, we need to create the appropriate parent
		if cfg.UseEKParent == RSA_EK || cfg.UseEKParent == ECC_EK {
			var keytype tpm2.TPMTPublic
			switch cfg.UseEKParent {
			case RSA_EK:
				keytype = tpm2.RSAEKTemplate
			case ECC_EK:
				keytype = tpm2.ECCEKTemplate
			default:
				return &Token{}, fmt.Errorf("gdch-tpm-credential: unsupported ekparent: %s", cfg.UseEKParent)
			}
			// create the parent
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
				},
				InPublic: tpm2.New2B(keytype),
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't create pimaryEK: %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			// load it
			//var load_session_cleanup func() error
			parentSession, load_session_cleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't load policysession : %v", err)
			}
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
				},
				PolicySession: parentSession.Handle(),
				NonceTPM:      parentSession.NonceTPM(),
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't create policysecret: %v", err)
			}

		} else {

			// were' dealing with the default "H2" parent
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: key.Parent,
				InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't create primary (primary maybe RSAEK, not H2, try --useEKParent):   %v", err)
			}
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			parentSession = tpm2.PasswordAuth([]byte(parentPasswordAuth))
		}

		// now the actual key can get loaded from that parent
		svcAccountKeyResponse, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   tpm2.TPM2BName(primaryKey.Name),
				Auth:   parentSession,
			},
			InPublic:  key.Pubkey,
			InPrivate: key.Privkey,
		}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
		if err != nil {
			return &Token{}, fmt.Errorf("gdch-tpm-credential:can't load  rsaKey : %v", err)
		}
		if load_session_cleanup != nil {
			load_session_cleanup()
		}
		svcAccountKey = svcAccountKeyResponse.ObjectHandle

	} else {

		//  we deailing with a persistent handle

		// first load the parent if rsa_ek or ecc_ek
		if cfg.UseEKParent != H2 {
			var keytype tpm2.TPMTPublic
			switch cfg.UseEKParent {
			case RSA_EK:
				keytype = tpm2.RSAEKTemplate
			case ECC_EK:
				keytype = tpm2.ECCEKTemplate
			default:
				return &Token{}, fmt.Errorf("gdch-tpm-credential: unsupported ekparent: %s", cfg.UseEKParent)
			}
			var err error
			primaryKey, err = tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: primaryKey.ObjectHandle,
					Name:   tpm2.TPM2BName(primaryKey.Name),
					Auth:   parentSession,
				},
				InPublic: tpm2.New2B(keytype),
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't create pimaryEK: %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primaryKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()
			//var load_session_cleanup func() error
			parentSession, load_session_cleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't load policysession : %v", err)
			}
			defer load_session_cleanup()

			_, err = tpm2.PolicySecret{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHEndorsement,
					Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
					Auth:   tpm2.PasswordAuth([]byte(cfg.Parentpass)),
				},
				PolicySession: parentSession.Handle(),
				NonceTPM:      parentSession.NonceTPM(),
			}.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't create policysecret: %v", err)
			}

		}
		svcAccountKey = tpm2.TPMHandle(cfg.PersistentHandle)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: svcAccountKey,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// now initialize a session.  if pcrs are set, construct the TPMPCRSelections to validate against
	var se tpmjwt.Session
	if cfg.Pcrs != "" {

		pcrMap := make(map[uint][]byte)
		for _, v := range strings.Split(cfg.Pcrs, ",") {
			entry := strings.Split(v, ":")
			if len(entry) == 2 {
				uv, err := strconv.ParseUint(entry[0], 10, 32)
				if err != nil {
					return &Token{}, fmt.Errorf("gdch-tpm-credential:  could parse pcr values: %v", err)
				}
				hexEncodedPCR, err := hex.DecodeString(strings.ToLower(entry[1]))
				if err != nil {
					return &Token{}, fmt.Errorf("gdch-tpm-credential:  could parse pcr values: %v", err)
				}
				pcrMap[uint(uv)] = hexEncodedPCR
			}
		}
		_, pcrList, pcrHash, err := getPCRMap(tpm2.TPMAlgSHA256, pcrMap)
		if err != nil {
			return &Token{}, fmt.Errorf("gdch-tpm-credential:  could get pcrMap: %v", err)
		}

		sel := []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
			},
		}

		// if the parent was not h2, we're assuming it was duplicated using
		//  tpmcopy utility.  In this case the key is always bond with s apsecific policy
		// see https://github.com/salrashid123/tpmcopy/tree/main#bound-key-policy
		if cfg.UseEKParent != H2 {
			// initialize a bound key policy to duplicate select + PCRs
			se, err = tpmjwt.NewPCRAndDuplicateSelectSession(rwr, sel, tpm2.TPM2BDigest{Buffer: pcrHash}, []byte(cfg.Keypass), primaryKey.Name, encryptionSessionHandle)
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't create authsession: %v", err)
			}
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
		} else {

			// if its h2, just iniialzie a regular PCR session
			se, err = tpmjwt.NewPCRSession(rwr, sel, tpm2.TPM2BDigest{Buffer: pcrHash}, encryptionSessionHandle)
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential:  could get NewPCRSession: %v", err)
			}
		}

	} else if keyPasswordAuth != "" {

		if cfg.UseEKParent != H2 {

			se, err = tpmjwt.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(cfg.Keypass), primaryKey.Name, encryptionSessionHandle)
			if err != nil {
				return &Token{}, fmt.Errorf("gdch-tpm-credential: can't create authSession: %v", err)
			}
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ekoutPub)))
		} else {
			se, err = tpmjwt.NewPasswordAuthSession(rwr, []byte(keyPasswordAuth), encryptionSessionHandle)
		}
	}
	if err != nil {
		return &Token{}, fmt.Errorf("gdch-tpm-credential:  could not initialize Key: %v", err)
	}

	ctx := context.Background()

	config := &tpmjwt.TPMConfig{
		TPMDevice:        cfg.TPMCloser,
		Handle:           svcAccountKey,
		AuthSession:      se,
		EncryptionHandle: encryptionSessionHandle,
	}
	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		return &Token{}, fmt.Errorf("gdch-tpm-credential: Error signing %v", err)
	}

	tpmjwt.SigningMethodTPMES256.Override()
	jwt.MarshalSingleStringAsArray = false

	// otherwise, just sign a JWT and return it (i.,e JWT AccessToken)
	iat := time.Now()

	expireInSeconds := DEFAULT_STSJWTExpireIn
	if cfg.STSJWTExpireIn > 0 {
		expireInSeconds = cfg.STSJWTExpireIn
	}
	exp := iat.Add(time.Duration(expireInSeconds) * time.Second)

	claims := &jwt.RegisteredClaims{
		IssuedAt:  &jwt.NumericDate{iat},
		ExpiresAt: &jwt.NumericDate{exp},
		Issuer:    fmt.Sprintf("system:serviceaccount:%s:%s", cfg.ProjectID, cfg.ServiceAccountName),
		Audience:  []string{cfg.TokenURI},
		Subject:   fmt.Sprintf("system:serviceaccount:%s:%s", cfg.ProjectID, cfg.ServiceAccountName),
	}

	token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMES256, claims)

	token.Header["kid"] = cfg.KeyID
	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		return &Token{}, fmt.Errorf("gdch-tpm-credential: Error signing %v", err)
	}

	stsTLSConfig := &tls.Config{
		ServerName: cfg.STSServerName,
		RootCAs:    cfg.STSServerRootCA,
	}

	stsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: stsTLSConfig,
		},
	}

	stsTokenSource, err := salsts.STSTokenSource(
		&salsts.STSTokenConfig{
			TokenExchangeServiceURI: cfg.TokenURI,
			SubjectTokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: tokenString,
			}),
			SubjectTokenType:   "urn:k8s:params:oauth:token-type:serviceaccount",
			RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			HTTPClient:         stsClient,
		},
	)
	if err != nil {
		return &Token{}, fmt.Errorf("gdch-tpm-credential: Error get token from tokensource: %v", err)
	}

	tok, err := stsTokenSource.Token()
	if err != nil {
		return &Token{}, fmt.Errorf("gdch-tpm-credential: Error get token from tokensource: %v", err)
	}

	return &Token{
		AccessToken: tok.AccessToken,
		TokenType:   tok.TokenType,
		ExpiresIn:   int64(time.Until(tok.Expiry).Seconds()),
	}, nil
}

func getEnv(key, fallback string, fromArg string) string {
	if fromArg != "" {
		return fromArg
	}
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getPCRMap(algo tpm2.TPMAlgID, pcrMap map[uint][]byte) (map[uint][]byte, []uint, []byte, error) {

	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm2.TPMAlgSHA1 {
		hsh = sha1.New()
	}
	if algo == tpm2.TPMAlgSHA256 {
		hsh = sha256.New()
	}

	if algo == tpm2.TPMAlgSHA1 || algo == tpm2.TPMAlgSHA256 {
		for uv, v := range pcrMap {
			pcrMap[uint(uv)] = v
			hsh.Write(v)
		}
	} else {
		return nil, nil, nil, fmt.Errorf("gdch-tpm-credential: unknown Hash Algorithm for TPM PCRs %v", algo)
	}

	pcrs := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		pcrs = append(pcrs, k)
	}

	return pcrMap, pcrs, hsh.Sum(nil), nil
}
