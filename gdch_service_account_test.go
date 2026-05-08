package gdchtpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/stretchr/testify/require"
)

const (
	swTPMPath = "127.0.0.1:2321"
	STSSNI    = "stsgcdh-995081019036.us-central1.run.app"
	STSURL    = "https://stsgcdh-995081019036.us-central1.run.app/authenticate"
)

func loadH2Key(rwr transport.TPM, persistentHandle uint, keyFilePath string, saPEM []byte) (tpm2.TPMHandle, tpm2.TPM2BName, func(), error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	pvk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	pv := pvk.(*ecdsa.PrivateKey)
	pk := pv.PublicKey
	eccTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))), //pk.X.Bytes(), // pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))), //pk.Y.Bytes(), // pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))),
				},
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgECC,
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgECC,
			&tpm2.TPM2BECCParameter{Buffer: pv.D.FillBytes(make([]byte, len(pv.D.Bytes())))},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectPublic: tpm2.New2B(eccTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  tpm2.New2B(eccTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: loadResponse.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	closer := func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}

	// _, err = tpm2.EvictControl{
	// 	Auth: tpm2.TPMRHOwner,
	// 	ObjectHandle: &tpm2.NamedHandle{
	// 		Handle: loadResponse.ObjectHandle,
	// 		Name:   pub.Name,
	// 	},
	// 	PersistentHandle: tpm2.TPMHandle(persistentHandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	return 0, tpm2.TPM2BName{}, nil, err
	// }

	tkf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: true,
		Parent:    tpm2.TPMRHOwner,
		Pubkey:    tpm2.New2B(eccTemplate),
		Privkey:   importResponse.OutPrivate,
	}
	b := new(bytes.Buffer)
	err = keyfile.Encode(b, tkf)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	err = os.WriteFile(keyFilePath, b.Bytes(), 0644)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	return loadResponse.ObjectHandle, pub.Name, closer, nil
}

func loadEKKey(rwr transport.TPM, parent tpm2.TPMTPublic, persistentHandle uint, keyFilePath string, saPEM []byte) (tpm2.TPMHandle, tpm2.TPM2BName, func(), error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(parent),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	block, _ := pem.Decode([]byte(saPEM))
	if block == nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	pvk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	pv := pvk.(*ecdsa.PrivateKey)
	pk := pv.PublicKey
	eccTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),

		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))), //pk.X.Bytes(), // pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))), //pk.Y.Bytes(), // pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))),
				},
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgECC,
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgECC,
			&tpm2.TPM2BECCParameter{Buffer: pv.D.FillBytes(make([]byte, len(pv.D.Bytes())))},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importSession, import_session_cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer import_session_cleanup()

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(nil),
		},
		PolicySession: importSession.Handle(),
		NonceTPM:      importSession.NonceTPM(),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   importSession,
		},
		ObjectPublic: tpm2.New2B(eccTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	import_session_cleanup()

	importSession2, import_session_cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	defer import_session_cleanup2()

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(nil),
		},
		PolicySession: importSession2.Handle(),
		NonceTPM:      importSession2.NonceTPM(),
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   importSession2,
		},
		InPublic:  tpm2.New2B(eccTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: loadResponse.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}

	closer := func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadResponse.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}

	// _, err = tpm2.EvictControl{
	// 	Auth: tpm2.TPMRHOwner,
	// 	ObjectHandle: &tpm2.NamedHandle{
	// 		Handle: loadResponse.ObjectHandle,
	// 		Name:   pub.Name,
	// 	},
	// 	PersistentHandle: tpm2.TPMHandle(persistentHandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	return 0, tpm2.TPM2BName{}, nil, err
	// }

	tkf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: true,
		Parent:    tpm2.TPMRHEndorsement,
		Pubkey:    tpm2.New2B(eccTemplate),
		Privkey:   importResponse.OutPrivate,
	}
	b := new(bytes.Buffer)
	err = keyfile.Encode(b, tkf)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	err = os.WriteFile(keyFilePath, b.Bytes(), 0644)
	if err != nil {
		return 0, tpm2.TPM2BName{}, nil, err
	}
	return loadResponse.ObjectHandle, pub.Name, closer, nil
}

// TODO
// func TestPersistentHandleCredentials(t *testing.T) {
// 	tpmDevice, err := net.Dial("tcp", swTPMPath)
// 	require.NoError(t, err)
// 	defer tpmDevice.Close()

// 	rwr := transport.FromReadWriter(tpmDevice)

// 	tempDir := t.TempDir()
// 	filePath := filepath.Join(tempDir, "key.pem")

// 	persistentHandle := 0x81008001

// 	k, err := os.ReadFile("example/certs/workload1.key")
// 	require.NoError(t, err)
// 	_, _, closer, err := loadH2Key(rwr, uint(persistentHandle), filePath, k, tpm2.TPMAlgRSASSA)
// 	require.NoError(t, err)
// 	defer closer()
// }

func TestKeyFileH2Credentials(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	persistentHandle := 0x81008002
	k, err := os.ReadFile("example/certs/workload1.key")
	require.NoError(t, err)

	_, _, closer, err := loadH2Key(rwr, uint(persistentHandle), filePath, k)
	require.NoError(t, err)
	closer()

	keyFileBytes, err := os.ReadFile(filePath)
	require.NoError(t, err)

	resp, err := NewGDCHTPMCredential(&GDCHTPMConfig{
		TPMCloser:        tpmDevice,
		PersistentHandle: uint(persistentHandle),
		KeyFileBytes:     keyFileBytes,

		STSServerName: STSSNI,

		ServiceAccountName: "sa_name",
		ProjectID:          "testproject",
		TokenURI:           STSURL,
		KeyID:              "1234",
		STSAudience:        "https://management-kube.apiserver.your-org-1.zone1.google.gdch.test",

		Parentpass:  "",
		Keypass:     "",
		UseEKParent: H2,
	})
	require.NoError(t, err)

	require.Equal(t, resp.AccessToken, "fake_access_token")
	//t.Log(resp.AccessToken)
}

func TestKeyFileEKRSACredentials(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	k, err := os.ReadFile("example/certs/workload1.key")
	require.NoError(t, err)

	persistentHandle := 0x810080010
	_, _, closer, err := loadEKKey(rwr, tpm2.RSAEKTemplate, uint(persistentHandle), filePath, k)
	require.NoError(t, err)
	closer()

	keyFileBytes, err := os.ReadFile(filePath)
	require.NoError(t, err)

	resp, err := NewGDCHTPMCredential(&GDCHTPMConfig{
		TPMCloser:        tpmDevice,
		PersistentHandle: uint(persistentHandle),
		KeyFileBytes:     keyFileBytes,

		STSServerName: STSSNI,

		ServiceAccountName: "sa_name",
		ProjectID:          "testproject",
		TokenURI:           STSURL,
		KeyID:              "1234",
		STSAudience:        "https://management-kube.apiserver.your-org-1.zone1.google.gdch.test",

		Parentpass:  "",
		Keypass:     "",
		UseEKParent: RSA_EK,
	})
	require.NoError(t, err)

	require.Equal(t, resp.AccessToken, "fake_access_token")
	//t.Log(resp.AccessToken)
}

func TestKeyFileEKECCCredentials(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "key.pem")

	k, err := os.ReadFile("example/certs/workload1.key")
	require.NoError(t, err)

	persistentHandle := 0x81008008
	_, _, closer, err := loadEKKey(rwr, tpm2.ECCEKTemplate, uint(persistentHandle), filePath, k)
	require.NoError(t, err)
	closer()

	keyFileBytes, err := os.ReadFile(filePath)
	require.NoError(t, err)

	resp, err := NewGDCHTPMCredential(&GDCHTPMConfig{
		TPMCloser:        tpmDevice,
		PersistentHandle: uint(persistentHandle),
		KeyFileBytes:     keyFileBytes,

		STSServerName: STSSNI,

		ServiceAccountName: "sa_name",
		ProjectID:          "testproject",
		TokenURI:           STSURL,
		KeyID:              "1234",
		STSAudience:        "https://management-kube.apiserver.your-org-1.zone1.google.gdch.test",

		Parentpass:  "",
		Keypass:     "",
		UseEKParent: ECC_EK,
	})
	require.NoError(t, err)

	require.Equal(t, resp.AccessToken, "fake_access_token")
	//t.Log(resp.AccessToken)
}
