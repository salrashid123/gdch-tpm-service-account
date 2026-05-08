package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm/tpmutil"
	gdchtpm "github.com/salrashid123/gdch-tpm-service-account"
)

const (
	parent_pass_var = "TPM_PARENT_AUTH"
	key_pass_var    = "TPM_KEY_AUTH"
)

var (
	// common options
	tpmPath          = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	persistentHandle = flag.Uint("persistentHandle", 0x81010002, "Handle value")
	keyfilepath      = flag.String("keyfilepath", "", "TPM Encrypted KeyFile")
	parentPass       = flag.String("parentPass", "", "Passphrase for the owner handle (will use TPM_PARENT_AUTH env var)")
	keyPass          = flag.String("keyPass", "", "Passphrase for the key handle (will use TPM_KEY_AUTH env var)")
	pcrs             = flag.String("pcrs", "", "PCR Bound value (increasing order, comma separated)")
	useEKParent      = flag.String("useEKParent", "", "Use endorsement (rsa_ek or ecc_ek) as parent (not h2)")

	caCertificate = flag.String("caCertificate", "", "STS Server CA Certificate (default: )")
	stsServerName = flag.String("stsServerName", "", "SNI of the STS server (default: )")
	keyID         = flag.String("keyID", "", "KeyID for the private key (default: )")

	svcAccountName = flag.String("svcAccountName", "", "Service Account Name")
	projectID      = flag.String("projectID", "", "Project ID (default: )")
	tokenURI       = flag.String("tokenURI", "", "STSServer URI (default: )")
	stsAudience    = flag.String("stsAudience", "", "Audience for the STS request")

	rawOutput = flag.Bool("rawOutput", false, "return just the token, nothing else")

	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
	version               = flag.Bool("version", false, "print version")

	Commit, Tag, Date string
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {

	flag.Parse()

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		return 0
	}

	parentPasswordAuth := getEnv(parent_pass_var, "", *parentPass)
	keyPasswordAuth := getEnv(key_pass_var, "", *keyPass)

	rwr, err := openTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gdch-tpm-credentiall: Error opening TPM %v", err)
		return 1
	}
	defer rwr.Close()

	keyFileBytes, err := os.ReadFile(*keyfilepath)
	if err != nil {
		fmt.Printf("gdch-tpm-credential: did not read keyfile: %v", err)
		return 1
	}

	var caCertPool *x509.CertPool

	if *caCertificate != "" {
		caCert, err := os.ReadFile(*caCertificate)
		if err != nil {
			fmt.Printf("gdch-tpm-credential: did not read tlsCA: %v", err)
			return 1
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	} else {
		caCertPool, err = x509.SystemCertPool()
	}
	var keyType gdchtpm.ParentKeyType
	switch *useEKParent {
	case gdchtpm.RSA_EK.String():
		keyType = gdchtpm.RSA_EK
	case gdchtpm.ECC_EK.String():
		keyType = gdchtpm.ECC_EK
	case gdchtpm.H2.String():
		keyType = gdchtpm.H2
	default:
		keyType = gdchtpm.H2
	}

	resp, err := gdchtpm.NewGDCHTPMCredential(&gdchtpm.GDCHTPMConfig{
		TPMCloser:        rwr,
		PersistentHandle: uint(*persistentHandle),
		KeyFileBytes:     keyFileBytes,

		STSServerRootCA: caCertPool,
		STSServerName:   *stsServerName,

		ServiceAccountName: *svcAccountName,
		ProjectID:          *projectID,
		TokenURI:           *tokenURI,
		KeyID:              *keyID,
		STSAudience:        *stsAudience,

		SessionEncryptionName: *sessionEncryptionName,
		Parentpass:            parentPasswordAuth,
		Keypass:               keyPasswordAuth,
		Pcrs:                  *pcrs,
		UseEKParent:           keyType,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "gdch-tpm-credential: Error getting credentials %v", err)
		return 1
	}

	if *rawOutput {
		fmt.Println(resp.AccessToken)
		return 0
	}

	m, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gdch-tpm-credential: Error marshalling processCredential output %v", err)
		return 1
	}

	fmt.Println(string(m))
	return 0
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
