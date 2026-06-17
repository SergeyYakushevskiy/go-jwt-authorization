package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	TokenMgr *TokenManager

	NoTokenMgrErr error = errors.New("Токен-менеджер не задан")

	emptySecretErr error = errors.New("jwt-секрет не задан")

	invalidTokenErr error = errors.New("невалидный токен")
	TokenExpiredErr error = errors.New("время жизни токена истекло")
)

type TokenManager struct {
	secretKey []byte

	refreshTokenExpired time.Duration
	accessTokenExpired  time.Duration
}

func NewTokenManager(secretKey []byte, refreshTokenExpired uint32, accessTokenExpired uint32) (*TokenManager, error) {

	if len(secretKey) == 0 {
		return nil, emptySecretErr
	}
	return &TokenManager{
		secretKey:           secretKey,
		refreshTokenExpired: time.Duration(refreshTokenExpired),
		accessTokenExpired:  time.Duration(refreshTokenExpired),
	}, nil
}

/*
	Метод генерации токена

В зависимости от параметра refreshTokenEnabled будет указано время жизни токена:
  - true: время жизни refresh-токена
  - false: время жизни access-токена
*/
func GenerateToken(userId string, refreshTokenEnabled bool) (string, string, error) {
	if TokenMgr == nil {
		return "", "", NoTokenMgrErr
	}
	var expTimestamp time.Time
	if refreshTokenEnabled {
		expTimestamp = time.Now().Add(TokenMgr.refreshTokenExpired * time.Second)
	} else {
		expTimestamp = time.Now().Add(TokenMgr.accessTokenExpired * time.Second)
	}
	tokenId, err := uuid.NewV7()
	if err != nil {
		return "", "", err
	}
	claims := jwt.RegisteredClaims{
		ID:        tokenId.String(),
		Audience:  jwt.ClaimStrings{userId},
		ExpiresAt: jwt.NewNumericDate(expTimestamp),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(TokenMgr.secretKey)
	if err != nil {
		return "", "", err
	}
	return token, tokenId.String(), err
}

func ValidateToken(signedToken string) (*jwt.RegisteredClaims, error) {
	if TokenMgr == nil {
		return nil, NoTokenMgrErr
	}
	token, err := jwt.ParseWithClaims(
		signedToken,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(TokenMgr.secretKey), nil
		},
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, invalidTokenErr
	}
	return claims, nil
}
