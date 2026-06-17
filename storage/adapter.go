package storage

import (
	"errors"
	"strconv"

	"github.com/SergeyYakushevskiy/jwt-authorization/model"
	"github.com/restream/reindexer/v5"
	_ "github.com/restream/reindexer/v5/bindings/cproto"
	"github.com/rs/zerolog/log"
)

const (
	jwtNsp          = "jwt"
	profilesNsp     = "profiles"
	credentialsNsp  = "credentials"
	JwtBlacklistNsp = "jwt_blacklist"
)

var (
	NoDBConnectionErr error = errors.New("отсутствует подключение к БД")
	UserNotFoundErr   error = errors.New("пользователь не найден")
	DbQueryErr        error = errors.New("ошибка взаимодействия с БД")
)

type Session struct {
	Jti    string
	Device string
}

func New(config *model.DbConfig) (*reindexer.Reindexer, error) {
	addr := "cproto://" + config.Host + ":" + strconv.Itoa(int(config.Port)) + "/" + config.DbName
	db, err := reindexer.NewReindex(addr, reindexer.WithCreateDBIfMissing())
	if err != nil {
		return nil, err
	}
	log.Info().Msgf("открыто соединение с БД по адресу: %s", addr)
	if err = db.OpenNamespace(profilesNsp, reindexer.DefaultNamespaceOptions(), model.Profile{}); err != nil {
		return nil, err
	}
	if err = db.OpenNamespace(credentialsNsp, reindexer.DefaultNamespaceOptions(), model.Credentials{}); err != nil {
		return nil, err
	}
	if err = db.OpenNamespace(jwtNsp, reindexer.DefaultNamespaceOptions(), model.Jwt{}); err != nil {
		return nil, err
	}
	if err = db.OpenNamespace(JwtBlacklistNsp, reindexer.DefaultNamespaceOptions(), model.JwtBlacklist{}); err != nil {
		return nil, err
	}
	return db, nil
}

func InsertProfile(conn *reindexer.Reindexer, profile *model.Profile) (int, error) {
	return conn.Insert(profilesNsp, profile)
}

func InsertCredentials(conn *reindexer.Reindexer, credentials *model.Credentials) (int, error) {
	return conn.Insert(credentialsNsp, credentials, "id=serial()")
}

func InsertJwt(conn *reindexer.Reindexer, jwt *model.Jwt) (int, error) {
	return conn.Insert(jwtNsp, jwt, "id=serial()")
}

func UpdateJwt(conn *reindexer.Reindexer, jwt *model.Jwt) error {
	return conn.Query(jwtNsp).
		Where("id", reindexer.EQ, jwt.ID).
		Set("refresh_jti", jwt.RefreshJti).
		Update().Error()
}

func IsRefreshTokenRevoked(conn *reindexer.Reindexer, tokenId string) bool {
	_, found := conn.Query(jwtNsp).
		Where("refresh_jti", reindexer.EQ, tokenId).
		Where("is_revoked", reindexer.EQ, 1).
		Get()
	return found
}

func GetSessionsByProfileId(conn *reindexer.Reindexer, profileId string) (*[]Session, error) {
	var sessions []Session

	iterator := conn.Query(jwtNsp).
		Where("profile_id", reindexer.EQ, profileId).
		Where("is_revoked", reindexer.EQ, 0).
		Select("refresh_jti", "device").
		Exec()

	defer iterator.Close()

	if err := iterator.Error(); err != nil {
		return nil, UserNotFoundErr
	}

	for iterator.Next() {
		record := iterator.Object().(*model.Jwt)
		sessions = append(sessions, Session{Jti: record.RefreshJti, Device: record.Device})
	}

	return &sessions, nil
}

func RevokeRefreshJwtByTokenID(conn *reindexer.Reindexer, tokenId string) error {
	return conn.Query(jwtNsp).
		Where("refresh_jti", reindexer.EQ, tokenId).
		Set("is_revoked", 1).
		Update().Error()
}

func RevokeAccessJwtByTokenID(conn *reindexer.Reindexer, tokenId string) (int, error) {
	return conn.Insert(JwtBlacklistNsp, model.JwtBlacklist{AccessJti: tokenId}, "id=serial()")
}

func GetProfileById(conn *reindexer.Reindexer, profileId string) (*model.Profile, error) {
	record, found := conn.Query(profilesNsp).
		Where("id", reindexer.EQ, profileId).
		Get()
	if !found {
		return nil, UserNotFoundErr
	}
	return record.(*model.Profile), nil

}

func GetCredentialsByLogin(conn *reindexer.Reindexer, login string) (*model.Credentials, error) {
	record, found := conn.Query(credentialsNsp).
		Where("login", reindexer.EQ, login).
		Get()
	if !found {
		return nil, UserNotFoundErr
	}
	return record.(*model.Credentials), nil
}

func GetCredentialsByProfileId(conn *reindexer.Reindexer, profileId string) (*model.Credentials, error) {
	record, found := conn.Query(credentialsNsp).
		Where("profile_id", reindexer.EQ, profileId).
		Get()
	if !found {
		return nil, UserNotFoundErr
	}
	return record.(*model.Credentials), nil
}

func ExistsByLogin(conn *reindexer.Reindexer, login string) bool {
	_, exists := conn.Query(credentialsNsp).
		Where("login", reindexer.EQ, login).
		Select("id").Get()
	return exists
}

func IsBlockedByProfileID(conn *reindexer.Reindexer, profileId string) bool {
	_, found := conn.Query(credentialsNsp).
		Where("profile_id", reindexer.EQ, profileId).
		Where("is_blocked", reindexer.EQ, 1).
		Get()
	if !found {
		return false
	}
	return true
}

func DeleteProfileByID(conn *reindexer.Reindexer, profileId string) (int, error) {
	return conn.Query(profilesNsp).Where("id", reindexer.EQ, profileId).Delete()
}

func DeleteJwtByProfileID(conn *reindexer.Reindexer, profileId string) (int, error) {
	return conn.Query(jwtNsp).Where("profile_id", reindexer.EQ, profileId).Delete()
}
