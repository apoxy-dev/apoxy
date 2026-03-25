Guide the user through setting up Apple code signing and notarization for the CLI release pipeline. Walk through each step interactively — do NOT dump all steps at once. After each step, wait for the user to confirm completion before moving to the next.

Use the AskUserQuestion tool with selectable options at decision points and when waiting for user input.

## Step 1: Prerequisites Check

Ask the user to confirm they have:
- An Apple Developer Program **organization** account (not personal)
- Access to https://developer.apple.com/account
- Access to https://appstoreconnect.apple.com
- `openssl` installed locally
- `gh` CLI installed and authenticated to the `apoxy-dev/apoxy` repo
- `rcodesign` installed (`cargo install apple-codesign`)

## Step 2: Generate Private Key

Run this for the user:
```bash
openssl genrsa -out developer_id.key 2048
```

Confirm the file was created.

## Step 3: Generate CSR

Run this for the user:
```bash
openssl req -new -key developer_id.key \
  -out developer_id.csr \
  -subj "/emailAddress=support@apoxy.dev/CN=Apoxy, Inc/C=US"
```

Confirm the file was created.

## Step 4: Upload CSR to Apple (Manual)

Tell the user:
1. Go to https://developer.apple.com/account/resources/certificates/add
2. Select **"Developer ID Application"** (NOT "Developer ID Installer")
3. Upload the `developer_id.csr` file generated in the previous step
4. Download the resulting `.cer` file

Ask the user to provide the path to the downloaded `.cer` file (usually `~/Downloads/developerID_application.cer`).

## Step 5: Convert to .p12

Generate a random password and convert the cert:
```bash
P12_PASSWORD=$(openssl rand -base64 24)
echo "Generated P12 password: $P12_PASSWORD"
echo "$P12_PASSWORD" > .p12-password.txt

# Convert Apple's DER cert to PEM
openssl x509 -inform der -in <DOWNLOADED_CER_PATH> -out developer_id.pem

# Download Apple's intermediate cert
curl -sO https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
openssl x509 -inform der -in DeveloperIDG2CA.cer -out DeveloperIDG2CA.pem

# Bundle into .p12 (MUST use -legacy for rcodesign compatibility)
# OpenSSL 3.x defaults to AES-256-CBC which rcodesign cannot decrypt.
openssl pkcs12 -export \
  -out developer_id.p12 \
  -inkey developer_id.key \
  -in developer_id.pem \
  -certfile DeveloperIDG2CA.pem \
  -password pass:$P12_PASSWORD \
  -legacy
```

Replace `<DOWNLOADED_CER_PATH>` with the path the user provided. Confirm the `.p12` was created and is non-empty.

## Step 6: Create App Store Connect API Key (Manual)

Tell the user:
1. Go to https://appstoreconnect.apple.com/access/integrations/api
2. Click "+" to generate a new key
3. Name it something like "CI Notarization"
4. Select **"Developer"** role
5. Download the `.p8` file (only downloadable once!)
6. Note the **Key ID** and **Issuer ID** shown on the page

Ask the user for:
- The **Issuer ID** (UUID format like `2bda9bb5-f36d-48f2-bd80-6493b0b6a051`)
- The **Key ID** (alphanumeric like `WLA58M3W6H`)
- The path to the downloaded `.p8` file (usually `~/Downloads/AuthKey_<KEY_ID>.p8`)

## Step 7: Generate Notary Key JSON

Run this for the user using the values they provided:
```bash
rcodesign encode-app-store-connect-api-key \
  <ISSUER_ID> \
  <KEY_ID> \
  <PATH_TO_P8>
```

Note: these are **positional arguments**, not flags. Capture the JSON output to a file:
```bash
rcodesign encode-app-store-connect-api-key <ISSUER_ID> <KEY_ID> <PATH_TO_P8> > notary-key.json
```

Verify the JSON has `issuer_id`, `key_id`, and `private_key` fields.

## Step 8: Upload GitHub Secrets

Run these for the user:
```bash
# Base64-encode the .p12
P12_B64=$(base64 < developer_id.p12 | tr -d '\n')

gh secret set APPLE_P12_BASE64 --body "$P12_B64" --repo apoxy-dev/apoxy
gh secret set APPLE_P12_PASSWORD --body "$(cat .p12-password.txt)" --repo apoxy-dev/apoxy
gh secret set APPLE_NOTARY_KEY_JSON --body "$(cat notary-key.json)" --repo apoxy-dev/apoxy
```

Confirm each secret was set successfully.

## Step 9: Cleanup Sensitive Files

Ask the user if they want to clean up the local sensitive files. If yes:
```bash
rm -f developer_id.key developer_id.csr developer_id.pem developer_id.p12 \
  DeveloperIDG2CA.cer DeveloperIDG2CA.pem .p12-password.txt notary-key.json
```

Remind them to keep the `.p8` file and password backed up securely (e.g., in a password manager) in case they need to rotate secrets later.

## Step 10: Verify

Tell the user to trigger a release to test:
```bash
git tag vX.Y.Z && git push origin vX.Y.Z
```

Then on a Mac after the release completes:
```bash
curl -sL https://github.com/apoxy-dev/apoxy/releases/download/vX.Y.Z/apoxy-darwin-arm64 -o apoxy
chmod +x apoxy
codesign -dv --verbose=4 ./apoxy
spctl --assess --type execute ./apoxy
```

Both commands should pass without errors.
