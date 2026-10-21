package cabundle

import (
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheck(t *testing.T) {
	r0 := readTestdata(t, "ca-certificates-bundle-20260413-r0.crt")
	r3 := readTestdata(t, "ca-certificates-bundle-20260909-r3.crt")
	tlsRoot := readTestdata(t, "emsign-root-tls-ca-g3.pem")

	cases := []struct {
		name    string
		bundle  []byte
		wantErr string
	}{
		{name: "wolfi 20260909-r3 bundle", bundle: r3},
		{name: "wolfi 20260413-r0 bundle", bundle: r0, wantErr: "emSign ECC Root CA - G3"},
		{name: "r3 plus emSign Root TLS CA - G3", bundle: append(append([]byte{}, r3...), tlsRoot...), wantErr: "emSign Root TLS CA - G3"},
		{name: "empty bundle", bundle: []byte{}, wantErr: "no certificates"},
		{name: "unparsable certificate", bundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), wantErr: "certificate 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.bundle)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Check() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Check() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// Each compromised intermediate, under either issuer, must fail on its SPKI.
func TestCheckIntermediates(t *testing.T) {
	r3 := readTestdata(t, "ca-certificates-bundle-20260909-r3.crt")
	seen := map[string]bool{}
	n := 0
	for rest := readTestdata(t, "emudhra-intermediates.pem"); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		n++
		bundle := append(append([]byte{}, r3...), pem.EncodeToMemory(block)...)
		err := Check(bundle)
		if err == nil || !strings.Contains(err.Error(), "SPKI SHA-256") {
			t.Fatalf("intermediate %d: Check() = %v, want an SPKI match", n, err)
		}
		for spki := range Distrusted.SPKISHA256 {
			if strings.Contains(err.Error(), spki) {
				seen[spki] = true
			}
		}
	}
	if n != 16 {
		t.Fatalf("read %d intermediates, want 16", n)
	}
	if len(seen) != len(Distrusted.SPKISHA256) {
		t.Fatalf("matched %d of %d distrusted SPKIs", len(seen), len(Distrusted.SPKISHA256))
	}
}

// firstBlock returns the first PEM block of a testdata file.
func firstBlock(t *testing.T, name string) *pem.Block {
	t.Helper()
	block, _ := pem.Decode(readTestdata(t, name))
	if block == nil {
		t.Fatalf("%s: no PEM block", name)
	}
	return block
}

// BoringSSL also loads X509 CERTIFICATE and TRUSTED CERTIFICATE blocks as certificates.
func TestCheckRelabeled(t *testing.T) {
	r3 := readTestdata(t, "ca-certificates-bundle-20260909-r3.crt")
	aux, err := asn1.Marshal(struct{ Trust []asn1.ObjectIdentifier }{
		Trust: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	certs := map[string]*pem.Block{
		"emSign Root TLS CA - G3": firstBlock(t, "emsign-root-tls-ca-g3.pem"),
		"EM DV TLS CA - G3B":      firstBlock(t, "emudhra-intermediates.pem"),
	}
	for want, block := range certs {
		for _, relabel := range []*pem.Block{
			{Type: "X509 CERTIFICATE", Bytes: block.Bytes},
			{Type: "TRUSTED CERTIFICATE", Bytes: append(append([]byte{}, block.Bytes...), aux...)},
		} {
			t.Run(want+" as "+relabel.Type, func(t *testing.T) {
				err := Check(append(append([]byte{}, r3...), pem.EncodeToMemory(relabel)...))
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("Check() = %v, want error naming %q", err, want)
				}
			})
		}
	}
}

func TestCheckRejectsUnreadableBlocks(t *testing.T) {
	r3 := readTestdata(t, "ca-certificates-bundle-20260909-r3.crt")
	cases := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{name: "unknown block type", extra: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x30, 0}})), wantErr: `unexpected block type "PUBLIC KEY"`},
		{name: "malformed block", extra: "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", wantErr: "PEM BEGIN lines"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(append(append([]byte{}, r3...), tc.extra...))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Check() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestCheckImage(t *testing.T) {
	r0 := readTestdata(t, "ca-certificates-bundle-20260413-r0.crt")
	r3 := readTestdata(t, "ca-certificates-bundle-20260909-r3.crt")
	amd64 := Variant{Platform: "linux/amd64", Bundle: r3}
	cases := []struct {
		name         string
		variants     []Variant
		allowMissing bool
		wantErr      string
	}{
		{name: "clean variants", variants: []Variant{amd64, {Platform: "linux/arm64", Bundle: r3}}},
		{name: "compromised second variant", variants: []Variant{amd64, {Platform: "linux/arm64", Bundle: r0}}, wantErr: "img linux/arm64: bundle trusts"},
		{name: "allowed missing bundle", variants: []Variant{amd64, {Platform: "linux/arm64", Missing: true}}, allowMissing: true},
		{name: "forbidden missing bundle", variants: []Variant{amd64, {Platform: "linux/arm64", Missing: true}}, wantErr: "img linux/arm64: no CA bundle"},
		{name: "allowMissing still checks present bundles", variants: []Variant{{Platform: "linux/amd64", Bundle: r0}, {Platform: "linux/arm64", Missing: true}}, allowMissing: true, wantErr: "img linux/amd64: bundle trusts"},
		{name: "no variants", wantErr: "no variants"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckImage("img", tc.variants, tc.allowMissing)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckImage() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CheckImage() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
