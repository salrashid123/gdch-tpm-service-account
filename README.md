## TPM credential for Google Distributed Cloud (GDC) Hosted

CLI which returns an `access_token` for ` Google Distributed Cloud Hosted` (`GCDH`) where the private key is embedded inside a `Trusted Platform Module (TPM)`.

Normally, when you create a service account credential for `gcdh`, the `privae_key` is present in its raw form directly inside the credential file:

* [GDCH: Manage service accounts](https://docs.cloud.google.com/distributed-cloud/hosted/docs/latest/gdcag/application/ao-user/iam/secure-service-account-keys)

```json
{
  "type": "gdch_service_account",
  "format_version": "1",
  "project": "project_name",
  "private_key_id": "abcdef1234567890",
  "private_key": "-----BEGIN PRIVATE KEY-----\nETC\n-----END PRIVATE KEY-----\n",
  "name": "sa_name",
  "ca_cert_path": "/path/to/root-ca.crt",
  "token_uri": "https://service-identity.<Domain>/authenticate",
  "universe_domain": "googleapis.com"
}
```

The private key is used to sign a JWT which is sent to an the `token_uri` STS server endpoint.  The endpoint verifies the JWT which includes the `key_id` and once validated, returns an `access_token`.

Overall, this poses some risk because the private key must be kept secure at all times as described in [Securing Service Accounts](https://docs.cloud.google.com/distributed-cloud/hosted/docs/latest/gdcag/application/ao-user/iam/secure-service-account-keys)

What this repo does is instead of having the raw private exposed directly, it is embedded into a TPM for enhanced security.  This essentially means the key itself is never exposed outside of the machine it was loaded into.

You can load the private key into the TPM either directly (`tpm2_import`) or transfer the private key remotely by first sealing it such that it can only get loaded by a specific, unique TPM (eg, `tpm2_duplicate`)

Furthermore, you can specify additional TPM policies such as requiring a passphrase PCR (eg, `tpm2_policypassword` or `tpm2_policypcr`).  The latter can help ensure the key can only be used by a VM with specific environment characteristics describable by PCR values.

>> NOTE: this repo and sample is *NOT* supported by google

---

### Configuration Options

You can set the following options on usage:

| Option | Description |
|:------------|-------------|
| **`--tpm-path`** | path to the TPM device (required default: `/dev/tpm0`) |
| **`--tokenURI`** | address of the STS Server (required default: ``) |
| **`--svcAccountName`** | name of the service account to request a token for (required default: ``) |
| **`--projectID`** | project id for the service account (required default: ``) |
| **`--stsServerName`** | SNI for the STS Server (required default: ``) |
| **`--persistentHandle`** | Persistent Handle for the HMAC key (default: `0x81010002`) |
| **`--keyfilepath`** | Path to the TPM HMAC credential file (required default: ``) |
| **`--parentPass`** | Passphrase for the owner handle (will use TPM_PARENT_AUTH env var) |
| **`--keyPass`** | Passphrase for the key handle (will use TPM_KEY_AUTH env var) |
| **`--pcrs`** | "PCR Bound slot:value (increasing order, comma separated)" |
| **`--rawOutput`** |  Return just the token, nothing else |
| **`--useEKParent`** | Use endorsement keys (`rsa_ek` or `ecc_ek` as parent (default: `h2`) |
| **`--tpm-session-encrypt-with-name`** | hex encoded TPM object 'name' to use with an encrypted session |

---

### QuickStart

This quickstart loads a gdc service account key into a [SoftwareTPM](https://github.com/stefanberger/swtpm).  You can ofcourse use a real TPM.

You'll also need golang and `tpm2_tools` installed for this to work

First create a configuration and extract the keys and its parameters

```bash
cd example/certs/
gdcloud iam service-accounts create svc_account_1 --project=project_name

gdcloud iam service-accounts keys create adc_file.json \
   --project=PROJECT --iam-account=NAME --ca-cert-path=CA_CERTIFICATE_PATH

cat adc_file.json | jq -r '.private_key' > private_key.pem

openssl ec -in private_key.pem -pubout -out public_key.pem

cat private_key.pem 
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0k2NHqeBtmYnTK/a
bhiUbMHPsoEC6UK3Jx23Pz4rpdShRANCAARSFcrRgGus8in7BQFZ1tqGgw60z1Ko
16IBndMUzLDPikNiz61+k70umAeiD1vIWf3OmaSWzHq0e4emwMZiqRzg
-----END PRIVATE KEY-----

export KEYID=`cat adc_file.json | jq -r '.private_key_id'`
export PROJECTID=`cat adc_file.json | jq -r '.project'`
export CA_CERT_FILE=`cat adc_file.json | jq -r '.ca_cert_path'`
export TOKEN_URI=`cat adc_file.json | jq -r '.token_uri'`
export SERVCIE_NAME=`cat adc_file.json | jq -r '.name'`
```

Now start the software tpm

```bash
cd example/
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2
```

### Import Key

To import the key directly into the TPM

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"

cd example/certs_import/

### create an H2 parent
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

## import the key
tpm2_import -C primary.ctx -G ecc:ecdsa -g sha256  -i ../certs/private_key.pem -u key.pub -r key.priv
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

### load and create a TPM-TSS PEM file
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o workload1_tpm_key.pem
```

where `workload1_tpm_key.pem` looks like

```text
-----BEGIN TSS2 PRIVATE KEY-----
MIIBEgYGZ4EFCgEDoAMBAQECBEAAAAEEWgBYACMACwAEAEAAAAAQABgACwADABAA
IFIVytGAa6zyKfsFAVnW2oaDDrTPUqjXogGd0xTMsM+KACBDYs+tfpO9LpgHog9b
yFn9zpmklsx6tHuHpsDGYqkc4ASBoACeACC1SaI+VMVnTFFZ00f0L0zNRov/E319
GbsABycz3KqwggAQ1XW/YGMbKdf8t5Zq1Z//xgjDA/TBMFbyWLSFm6DP+lpoq/Ui
7Qiz0ormj43GiVl24EE+inytTljE9noRXzGWpnvnyUdif6ZCKHGn6QG4fvXGik6H
ODT8jpZZxmF74nuB5soHrcEfBAKaPCmLHv1zMAoHVfGqgYQ2gr8=
-----END TSS2 PRIVATE KEY-----
```

so to get an access_token

```bash
gdch-tpm-service-account  \
    --keyfilepath=example/certs_import/workload1_tpm_key.pem \
    --stsServerName=service-identity.<Domain> \
    --svcAccountName=$SERVCIE_NAME --keyID=$KEYID \
    --tokenURI=$TOKEN_URI \
    --tpm-path="127.0.0.1:2321"
```

#### Duplicate Key

Key duplication involves a procedure where you remotely copy a key from your laptop in such a way that it can only get encoded into a target TPM.

For more information, see

- [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy)
- [tpm2_duplicateselect](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md#example-4-exporting-an-hmac-key-for-a-remote-tpm-and-restrict-it-from-further-exports)

I'm using `tpmcopy` for all these steps but you can use `tpm2_tools` stil if you want

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"

cd example/certs_duplicate/

### download tpmcopy (or build it directly from the it repo, your choice)
wget -O tpmcopy  https://github.com/salrashid123/tpmcopy/releases/download/v0.5.2/tpmcopy_0.5.2_linux_amd64
chmod u+x tpmcopy

### get the TPM's RSA public PEM key
### you can get this in many ways, (eg, from the EKCert, using tpm2_tools, etc)
###   eg https://github.com/salrashid123/tpmcopy/tree/main#usage-cli

tpmcopy --mode publickey --parentKeyType=rsa_ek -tpmPublicKeyFile=ek_public.pem --tpm-path="127.0.0.1:2321"

### --secret must be ParsePKCS8PrivateKey
tpmcopy --mode duplicate --keyType=ecc --secret=../certs/private_key.pem --eccScheme=ecc256 --password=bar  --hashScheme=sha256 -tpmPublicKeyFile=ek_public.pem -out=out.json
tpmcopy --mode import --parentKeyType=rsa_ek --in=out.json --out=tpmkey.pem --tpm-path="127.0.0.1:2321"
```

Now run the cli but remember to specify `-useEKParent=rsa_ek`

```bash
gdch-tpm-service-account \
    --keyfilepath=example/certs_duplicate/tpmkey.pem \
    --stsServerName=service-identity.<Domain> \
    --svcAccountName=$SERVCIE_NAME -keyID=$KEYID \
    --tokenURI=$TOKEN_URI -keyPass=bar -useEKParent=rsa_ek \
    --tpm-path="127.0.0.1:2321"
```

### Policies

You can also set TPM policies which govern the use of the embedded ECC key.  For example, you can specify it can only be used if a passphrase is provided or certain PCR values are present on the TPM

#### PasswordPolicy

Create a key with a passphrase

```bash
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_import -C primary.ctx -G ecc:ecdsa -g sha256  -i ../certs/private_key.pem -u key.pub -r key.priv -p bar
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o workload1_tpm_key.pem
```

now specify the passphrase when using the cli

```bash
gdch-tpm-service-account  \
    --keyfilepath=example/certs_import/workload1_tpm_key.pem \
    --stsServerName=service-identity.<Domain> \
    --svcAccountName=$SERVCIE_NAME --keyID=$KEYID \
    --tokenURI=$TOKEN_URI -keyPass=bar \
    --tpm-path="127.0.0.1:2321"
```

#### PCR Policy

To bind the key using a PCR value, specify the PCR policy directly.  For example, the following binds the key to a specific PCR value

```bash
### extend  pcr 23 beyond the default value
$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:23
  sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B

### create an h2
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

### create a pcr policy 
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat
tpm2_flushcontext session.dat

### import the key and specify the policy to use
tpm2_import -C primary.ctx -G ecc:ecdsa -g sha256  -i ../certs/private_key.pem -u key.pub -r key.priv -L policy.dat
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o workload1_tpm_key.pem
```

After this, you will need to spcify the PCRs to check against while getting the keys

```bash
gdch-tpm-service-account  \
    --keyfilepath=example/certs_import/workload1_tpm_key.pem \
    --stsServerName=service-identity.<Domain> \
    --svcAccountName=$SERVCIE_NAME --keyID=$KEYID \
    --tokenURI=$TOKEN_URI --pcrs=23:F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B \
    --tpm-path="127.0.0.1:2321"
```


#### Usage Cloud SDK Authentication

Also, while this is a command line utility and isn't easily consumable by google cloud SDK's for authentication, it should be easy enough to either

a) [GCE Metadata Server Emulator](https://github.com/salrashid123/gce_metadata_server) 

   * Modify the emulator to use these credentials instead of the service account key.   This emulator alredy has support for TPM based keys

b) Wrap using GCP SDK CredentialSource 

  * If you don't mind creating your own credential provider which wraps the TPM-sourced credential, you can use these as references:
  * [golang: TPM oauth2](https://github.com/salrashid123/oauth2)
  * [python: Cloud Auth TPM](https://github.com/salrashid123/cloud_auth_tpm)


c) Invoke custom process credential authentication library (see [reference](https://github.com/salrashid123/gcp-adc-tpm#acquire-access_token))

  * `golang`: [https://github.com/salrashid123/gcp_process_credentials_go](https://github.com/salrashid123/gcp_process_credentials_go)
  * `python`: [https://github.com/salrashid123/gcp_process_credentials_py](https://github.com/salrashid123/gcp_process_credentials_py)
  * `java`: [https://github.com/salrashid123/gcp_process_credentials_java](https://github.com/salrashid123/gcp_process_credentials_java)
  * `node`: [https://github.com/salrashid123/gcp_process_credentials_node](https://github.com/salrashid123/gcp_process_credentials_node)

### References

#### STS server

- [Security Token Service (STS) Credentials for HTTP and gRPC (rfc8693)](https://github.com/salrashid123/sts)

#### TPM Encryption

- [tpmcopy: Transfer RSA|ECC|AES|HMAC key to a remote Trusted Platform Module (TPM)](https://github.com/salrashid123/tpmcopy)
- [AEAD encryption using Trusted Platform Module (TPM)](https://github.com/salrashid123/go-tpm-wrapping)
- [Certificate Bound Tokens using Security Token Exchange Server (STS)](https://github.com/salrashid123/cert_bound_sts_server)
- [TPM Credential Source for Google Cloud SDK](https://github.com/salrashid123/gcp-adc-tpm)
- [Cloud Auth Library using Trusted Platform Module (TPM)](https://github.com/salrashid123/cloud_auth_tpm)

#### JWT

- [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)
- [golang-jwt for PKCS11](https://github.com/salrashid123/golang-jwt-pkcs11)

#### Kubernetes

- [Kubernetes Certificate Auth using Trusted Platform Module (TPM) keys](https://github.com/salrashid123/kubernetes_tpm_client)
- [Kubernetes Trusted Platform Module (TPM) DaemonSet](https://github.com/salrashid123/tpm_daemonset)
- [Kubernetes Trusted Platform Module (TPM) using Device Plugin and Gatekeeper](https://github.com/salrashid123/tpm_kubernetes)

---

### Test Local

If you want to test locally, you can run a local sts server which just returns a static token,

to use, start theserver
```bash
cd example/sts_server/

go run server.go -serverCert=certs/sts.crt -serverKey=certs/sts.key -workloadPublicKey=certs/public_key.pem
```

then invoke the clients

```bash

$ cat /etc/hosts
127.0.0.1	sts.domain.com

## run preconfigured vtpm:
cd example/
swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## for H2
go run cmd/main.go  -caCertificate=example/certs/root-ca.crt  \
   --keyfilepath=example/certs_import/workload1_tpm_key.pem  \
      --stsServerName=sts.domain.com   \
        --svcAccountName=sa_name --keyID=1234  \
           --tokenURI="https://sts.domain.com:8081/authenticate"     --tpm-path="127.0.0.1:2321"

## for duplicated
go run cmd/main.go  -caCertificate=example/certs/root-ca.crt  \
   --keyfilepath=example/certs_duplicate/tpmkey.pem     --stsServerName=sts.domain.com  \
      --svcAccountName=sa_name -keyID=1234     \
      --tokenURI="https://sts.domain.com:8081/authenticate" -keyPass=bar -useEKParent=rsa_ek  \
         --tpm-path="127.0.0.1:2321"
```

If you want to generate a new CA, see [ca_scratchpad](https://github.com/salrashid123/ca_scratchpad).  Remember to specify ECC keys

### Test On Cloud Run

If you want to test the default certificates and setup against the sts demo server on cloud run, simply startup the `vtpm` config and specify the sts url
at `https://stsgcdh-995081019036.us-central1.run.app/authenticate`

for example

```bash
cd example/
swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2


export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l


go run cmd/main.go   \
   --keyfilepath=example/certs_import/workload1_tpm_key.pem  \
      --stsServerName=stsgcdh-995081019036.us-central1.run.app   \
        --svcAccountName=sa_name --keyID=1234  \
           --tokenURI="https://stsgcdh-995081019036.us-central1.run.app/authenticate"     --tpm-path="127.0.0.1:2321"

go run cmd/main.go  \
   --keyfilepath=example/certs_duplicate/tpmkey.pem     --stsServerName=stsgcdh-995081019036.us-central1.run.app   \
      --svcAccountName=sa_name -keyID=1234     \
      --tokenURI="https://stsgcdh-995081019036.us-central1.run.app/authenticate"  -keyPass=bar -useEKParent=rsa_ek  \
         --tpm-path="127.0.0.1:2321"
```