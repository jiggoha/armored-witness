// Copyright 2023 The Armored Witness authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// TODO: comment for tool
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/kms/apiv1"
	"golang.org/x/mod/sumdb/note"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

type gcpResources struct {
	project     string
	keyRing     string
	keyName     string
	keyVersion  uint
	keyLocation string
}

type signer struct {
	// client  *kms.EkmClient
	client  *kms.KeyManagementClient
	keyHash uint32
	ctx     context.Context
	gcp     *gcpResources
}

// google.cloud.kms.v1.CryptoKeyVersion.name
// https://cloud.google.com/php/docs/reference/cloud-kms/latest/V1.CryptoKeyVersion
var kmsKeyName = "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%d"

func newSigner(ctx context.Context, c *kms.KeyManagementClient, gcp *gcpResources) (*signer, error) {
	s := &signer{}

	s.client = c
	s.ctx = ctx
	s.gcp = gcp

	// Set keyHash.
	req := &kmspb.GetPublicKeyRequest{
		// TODO: pull this out to main.
		Name: fmt.Sprintf(kmsKeyName, s.gcp.project, s.gcp.keyLocation, s.gcp.keyRing,
			s.gcp.keyName, s.gcp.keyVersion),
	}
	resp, err := c.GetPublicKey(ctx, req)
	if err != nil {
		return nil, err
	}
	decoded, _ := pem.Decode([]byte(resp.Pem))

	// Turn pem into first 4 bytes of SHA256 hash.
	h := sha256.New()
	h.Write(decoded.Bytes)
	firstFourBytes := h.Sum(nil)[:5]
	s.keyHash = binary.BigEndian.Uint32(firstFourBytes)

	return s, nil
}

func (s *signer) Name() string {
	// TODO: pull this out to main.
	return fmt.Sprintf(kmsKeyName, s.gcp.project, s.gcp.keyLocation, s.gcp.keyRing,
		s.gcp.keyName, s.gcp.keyVersion)
}

// KeyHash returns the first 4 bytes of the SHA256 hash of the signer's public
// key. It is used as a hint in identifying the correct key to verify with.
func (s *signer) KeyHash() uint32 {
	return s.keyHash
}

// Sign returns a signature for the given message.
func (s *signer) Sign(msg []byte) ([]byte, error) {
	req := &kmspb.AsymmetricSignRequest{
		// TODO: pull this out to main.
		Name: fmt.Sprintf(kmsKeyName, s.gcp.project, s.gcp.keyLocation, s.gcp.keyRing,
			s.gcp.keyName, s.gcp.keyVersion),
		Data: msg,
	}
	resp, err := s.client.AsymmetricSign(s.ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.GetSignature(), nil
	// base64 encoded signature
}

func main() {
	gcpProject := flag.String("project_name", "armored-witness",
		"TODO")
	keyRing := flag.String("key_ring", "armored-witness",
		"TODO")
	keyName := flag.String("key_name", "trusted-applet-ci",
		"TODO")
	keyVersion := flag.Uint("key_version", 1,
		"TODO")
	keyLocation := flag.String("key_location", "europe-west2",
		"TODO")
	firmwareFile := flag.String("firmware_file", "trusted_applet.elf",
		"TODO")

	flag.Parse()

	// if *gcpProject == "" {
	// 	log.Fatal("project_name is required.")
	// }
	// if *keyRing == "" {
	// 	log.Fatal("key_ring is required.")
	// }
	// if *keyName == "" {
	// 	log.Fatal("key_name is required.")
	// }
	// if *keyVersion == "" {
	// 	log.Fatal("key_version is required.")
	// }
	// if *firmwareFile == "" {
	// 	log.Fatal("firmware_file is required.")
	// }

	gcp := &gcpResources{
		project:     *gcpProject,
		keyRing:     *keyRing,
		keyName:     *keyName,
		keyVersion:  *keyVersion,
		keyLocation: *keyLocation,
	}

	ctx := context.Background()
	kmClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("failed to create KeyManagementClient: %v", err)
	}
	defer kmClient.Close()

	signer, err := newSigner(ctx, kmClient, gcp)
	if err != nil {
		log.Fatalf("failed to create signer: %v", err)
	}

	// Get note.
	firmwareBytes, err := os.ReadFile(*firmwareFile)
	if err != nil {
		log.Fatalf("failed to read firmware_file %q: %v", *firmwareFile, err)
	}
	msg, err := note.Sign(&note.Note{Text: string(firmwareBytes)}, signer)
	if err != nil {
		log.Fatalf("failed to sign note text from %q: %v", *firmwareFile, err)
	}
	fmt.Println(msg)
}
