package auth

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type TOTPResult struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

func GenerateTOTP(username string) (*TOTPResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Beamer",
		AccountName: username,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return nil, err
	}

	return &TOTPResult{
		Secret: key.Secret(),
		URI:    key.URL(),
	}, nil
}

func ValidateTOTPCode(secret, code string) bool {
	valid, _ := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:     1,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}
