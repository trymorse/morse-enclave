package media_test

import (
	"bytes"
	"os"
	"testing"
)

func TestAnImageSignedWithC2PAComesBackByteForByteSoItsManifestStillVerifies(t *testing.T) {
	cases := map[string]struct{ manifest, unrendered string }{
		"signed.png":  {manifest: "caBX", unrendered: "tEXt"},
		"signed.jpg":  {manifest: "jumdc2pa", unrendered: "\xff\xe1\x00\x12Exif"},
		"signed.webp": {manifest: "C2PA", unrendered: "EXIF"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile("testdata/c2pa/" + name)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(in, []byte(tc.manifest)) || !bytes.Contains(in, []byte(tc.unrendered)) {
				t.Fatalf("the fixture lacks its manifest %q or its metadata %q", tc.manifest, tc.unrendered)
			}
			if out := stripped(t, in); !bytes.Equal(out, in) {
				t.Errorf("the signed image changed: %d bytes became %d", len(in), len(out))
			}
		})
	}
}
