package main

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sony/sonyflake"
)

type jwtIdentityClaims struct {
	ID        string `json:"jti"`
	ExpiredAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	Email     string `json:"sub"`
	Aud       string `json:"aud"`
}

func newJwtIdentityClaims(id, creator string, lifeTimeDuration time.Duration) (jwtIdentityClaims, error) {

	if id == "" {
		return jwtIdentityClaims{}, fmt.Errorf("id cannot null")
	}

	return jwtIdentityClaims{
		ID:        id,
		ExpiredAt: time.Now().Add(lifeTimeDuration).UTC().Unix(),
		NotBefore: time.Now().UTC().Unix(),
		Issuer:    "user authorize type",
		IssuedAt:  time.Now().UTC().Unix(),
		Email:     "company name",
		Aud:       "test",
	}, nil

}

func (jwt jwtIdentityClaims) Valid() error {
	return nil
}

func main() {

	flake := sonyflake.NewSonyflake(sonyflake.Settings{})
	id, _ := flake.NextID()

	claim, err := newJwtIdentityClaims(fmt.Sprint(id), "nando", time.Hour*2)
	if err != nil {
		panic(err)
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodES512, claim).SigningString()

	if err != nil {
		panic(err)
	}

	var encodedString = base64.StdEncoding.EncodeToString([]byte(accessToken))
	fmt.Println("encoded JWT(base64):", encodedString)

	encodeJwt := jwt.EncodeSegment([]byte(accessToken))
	fmt.Println("encoded JWT(from jwt):", encodeJwt)

	var decodedByte, _ = base64.StdEncoding.DecodeString(encodedString)
	var decodedString = string(decodedByte)
	fmt.Println("decoded JWT(base64):", decodedString)

	decodeJwt, err := jwt.DecodeSegment(encodeJwt)
	if err != nil {
		panic(err)
	}
	decodeJwtString := string(decodeJwt)
	fmt.Println("decode JWT(from jwt(encoded)):", decodeJwtString)

}
