package keyring

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// kmsAPI is the subset of the AWS KMS client we use (also lets tests mock it).
type kmsAPI interface {
	Encrypt(ctx context.Context, in *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// KMSSealer seals master keys with an AWS KMS key (symmetric). The caller
// aad is bound through KMS EncryptionContext, which also shows up in
// CloudTrail.
type KMSSealer struct {
	api   kmsAPI
	keyID string
}

func NewKMSSealer(api kmsAPI, keyID string) (*KMSSealer, error) {
	if keyID == "" {
		return nil, errors.New("kms: key id/ARN/alias required")
	}
	return &KMSSealer{api: api, keyID: keyID}, nil
}

func (k *KMSSealer) Name() string { return "kms" }

func kmsContext(aad []byte) map[string]string {
	h := sha256.Sum256(aad)
	return map[string]string{"cryplus": base64.RawStdEncoding.EncodeToString(h[:])}
}

func (k *KMSSealer) Seal(ctx context.Context, pt, aad []byte) ([]byte, error) {
	out, err := k.api.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(k.keyID), Plaintext: pt, EncryptionContext: kmsContext(aad)})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

func (k *KMSSealer) Open(ctx context.Context, blob, aad []byte) ([]byte, error) {
	out, err := k.api.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(k.keyID), CiphertextBlob: blob, EncryptionContext: kmsContext(aad)})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

// NewKMSFromEnv uses the standard AWS credential chain plus
// CRYPLUS_KMS_KEY_ID and CRYPLUS_KEYFILE.
func NewKMSFromEnv(ctx context.Context, follower bool) (Provider, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	s, err := NewKMSSealer(kms.NewFromConfig(cfg), os.Getenv("CRYPLUS_KMS_KEY_ID"))
	if err != nil {
		return nil, err
	}
	return open(ctx, envOr("CRYPLUS_KEYFILE", "cryplus-keys.kms.json"), s, follower)
}
