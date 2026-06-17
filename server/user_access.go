package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SergeyYakushevskiy/jwt-authorization/auth"
	"github.com/SergeyYakushevskiy/jwt-authorization/model"
	"github.com/SergeyYakushevskiy/jwt-authorization/storage"
	"github.com/go-playground/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gitverse.ru/uzer_007/gogost/v2/gost34112012256"
)

var (
	validate = validator.New()
)

type Response struct {
	Status  string `json:"status"`
	Message any    `json:"message"`
}

/*
	Обработчик для регистрации

Метод: POST

Возвращаемые коды:
  - [http.StatusMethodNotAllowed] - неподдерживаемый метод;
  - [http.StatusBadRequest] - невалидные данные;
  - [http.StatusConflict] - имя пользователя уже занято;
  - [http.StatusInternalServerError] - ошибка обработки запроса;
  - [http.StatusCreated] - успешная регистрация.

При успешной регистрации вернёт поле profile_id
*/
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// валидация метода
	if r.Method != http.MethodPost {
		log.Error().Msgf("некорректный HTTP метод. URL: %s", r.URL)
		sendResponse(w, r, "метод не поддерживается", nil, http.StatusMethodNotAllowed)
		return
	}

	// получение данных
	var (
		raw []byte = make([]byte, 0, 50*4+50*4+50*4+20*4+64*4) // максимальный размер, занимаемый registerDto
		dto model.RegisterDto
	)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error().Err(err).Msg("не удалось считать входные данные при попытке регистрации")
		sendResponse(w, r, "некорректные входные данные", nil, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if err = json.Unmarshal(raw, &dto); err != nil {
		log.Error().Err(err).Msg("не удалось преобразовать входные данные в json при попытке регистрации")
		sendResponse(w, r, "некорректные входные данные", nil, http.StatusBadRequest)
		return
	}

	// валидация данных
	if err = validate.Struct(dto); err != nil {
		log.Error().Err(err).Msg("входные данные для регистрации не прошли валидацию")
		sendResponse(w, r, "некорректные входные данные", nil, http.StatusBadRequest)
		return
	}
	exists := storage.ExistsByLogin(DbConnection, dto.Login)
	if exists {
		log.Error().Err(err).Msgf("попытка регистрации пользователя с зарегистрированным логином. ip=%s", r.RemoteAddr)
		sendResponse(w, r, "логин уже занят", map[string]int{"status": 1}, http.StatusConflict)
		return
	}

	// вычисление хэша пароля
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		log.Error().Err(err).Msg("не удалось сгенерировать соль для хэша пароля")
		sendResponse(w, r, "ошибка при формировании хэша пароля", err.Error(), http.StatusInternalServerError)
		return
	}
	hash, err := gost34112012256.GostYescrypt(salt, []byte(dto.Password))
	if err != nil {
		log.Error().Err(err).Msg("не удалось сгенерировать хэш пароля")
		sendResponse(w, r, "ошибка при формировании хэша пароля", err.Error(), http.StatusInternalServerError)
		return
	}

	// регистрация
	profileId, err := uuid.NewV7()
	if err != nil {
		log.Error().Err(err).Msg("не удалось сгенерировать UUID пользователя")
		sendResponse(w, r, "ошибка при формировании ", err.Error(), http.StatusInternalServerError)
		return
	}
	profile := model.Profile{
		ID:         profileId.String(),
		Surname:    dto.Surname,
		Name:       dto.Name,
		Patronymic: dto.Patronymic,
		CreatedAt:  time.Now().Unix(),
	}
	res, err := storage.InsertProfile(DbConnection, &profile)
	if err != nil || res == 0 {
		log.Error().Err(err).Msg("не удалось записать данные в БД profiles")
		sendResponse(w, r, "ошибка при сохранении данных", nil, http.StatusInternalServerError)
		return
	}

	credentials := model.Credentials{
		ProfileID:    profile.ID,
		Login:        dto.Login,
		PasswordHash: gost34112012256.FormatGostYescryptHash(salt, hash),
	}

	// формирование ответа
	res, err = storage.InsertCredentials(DbConnection, &credentials)
	if err == nil && res == 1 {
		sendResponse(w, r, "регистрация прошла успешно", map[string]string{"profile_id": profileId.String()}, http.StatusCreated)
		return
	}
	sendResponse(w, r, "ошибка при сохранении данных", err.Error(), http.StatusInternalServerError)
	log.Error().Err(err).Msg("не удалось записать данные в БД credentials")
	res, err = storage.DeleteProfileByID(DbConnection, profile.ID)
	if res == 0 || err != nil {
		log.Error().Err(err).Msgf("не удалось удалить данные из БД profiles. result: %d", res)
	}
}

/*
	Обработчик для авторизации

Входные данные: [model.LoginDto]

Метод: POST

Возвращаемые коды:
  - [http.StatusMethodNotAllowed] - неподдерживаемый метод;
  - [http.StatusBadRequest] - невалидные данные;
  - [http.StatusConflict] - неверный логин или пароль;
  - [http.StatusInternalServerError] - ошибка обработки запроса, ошибка записи токена в хранилище;
  - [http.StatusCreated] - успешная авториазация.

При успешной авторизации возвращается JSON-тело с полями
  - refresh_token
  - access_token
*/
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// валидация метода
	if r.Method != http.MethodPost {
		log.Error().Msgf("некорректный HTTP метод. URL: %s", r.URL)
		sendResponse(w, r, "метод не поддерживается", nil, http.StatusMethodNotAllowed)
		return
	}
	// получение данных
	var (
		raw []byte
		dto model.LoginDto
	)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error().Err(err).Msg("не удалось считать входные данные при попытке авторизации")
		sendResponse(w, r, "некорректные входные данные", nil, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if err = json.Unmarshal(raw, &dto); err != nil {
		log.Error().Err(err).Msg("не удалось преобразовать входные данные в json при попытке авторизации")
		sendResponse(w, r, "некорректные входные данные", nil, http.StatusBadRequest)
		return
	}

	// валидация данных
	if err = validate.Struct(dto); err != nil {
		log.Error().Err(err).Msg("входные данные для авторизации не прошли валидацию")
		sendResponse(w, r, "некорректные входные данные", nil, http.StatusBadRequest)
		return
	}

	// аутентификация
	credentials, err := storage.GetCredentialsByLogin(DbConnection, dto.Login)
	if err != nil {
		log.Error().Err(err).Msgf("попытка авторизации по незарегистрированному логину. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "неверный логин или пароль", nil, http.StatusConflict)
		return
	}

	hashParts := strings.Split(credentials.PasswordHash, "$")
	salt, saltErr := base64.StdEncoding.DecodeString(hashParts[3])
	hash, hashErr := base64.StdEncoding.DecodeString(hashParts[4])
	if saltErr != nil || hashErr != nil {
		log.Error().Err(saltErr).Err(hashErr).Msgf("не удалось получить соль для хэша пользователя. ProfileID: %s", credentials.ProfileID)
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
		return
	}
	currentHash, err := gost34112012256.GostYescrypt(salt, []byte(dto.Password))
	if err != nil {
		log.Error().Err(err).Msgf("не удалось вычислить хэш пользователя. ProfileID: %s", credentials.ProfileID)
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
		return
	}
	if ok := subtle.ConstantTimeCompare(hash, currentHash) == 1; !ok {
		log.Error().Err(err).Msgf("введён неверный пароль. IP: %s, ProfileID: %s", r.RemoteAddr, credentials.ProfileID)
		sendResponse(w, r, "неверный логин или пароль", nil, http.StatusConflict)
		return
	}

	// генерация access и refresh-токенов
	refreshToken, refreshJti, refreshErr := auth.GenerateToken(credentials.ProfileID, true)
	accessToken, _, accessErr := auth.GenerateToken(credentials.ProfileID, true)
	if refreshErr != nil || accessErr != nil {
		log.Error().Err(refreshErr).Err(accessErr).Msgf("не удалось сгенерировать токены для пользователя. id=%s", credentials.ProfileID)
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
		return
	}

	// запись refresh-токена
	res, err := storage.InsertJwt(DbConnection, &model.Jwt{ProfileID: credentials.ProfileID, RefreshJti: refreshJti, Device: r.UserAgent(), IP: r.RemoteAddr, CreatedAt: time.Now().Unix()})
	if err != nil || res == 0 {
		log.Error().Err(err).Msg("не удалось записать данные о токене")
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
	}
	log.Info().Msgf("успешная авторизация. ProfileId: %s", credentials.ProfileID)
	sendResponse(w, r, "успешная авторизация", map[string]string{"refresh_token": refreshToken, "access_token": accessToken}, http.StatusCreated)
}

/*
	Обработчик выхода из учётной записи

Метод: POST

Возвращаемые коды:
  - [http.StatusMethodNotAllowed] - метод не поддерживается
  - [http.StatusInternalServerError] - не удалось отозвать токены
  - [http.StatusBadRequest] - не удалось получить / валидировать refresh-токен
  - [http.StatusOK] - успешный выход
*/
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// валидация метода
	if r.Method != http.MethodPost {
		log.Error().Msgf("некорректный HTTP метод. URL: %s", r.URL)
		sendResponse(w, r, "метод не поддерживается", nil, http.StatusMethodNotAllowed)
		return
	}

	// подготовка к удалению
	claims, ok := r.Context().Value("user_claims").(*jwt.RegisteredClaims)
	if !ok {
		log.Error().Msg("не удалось получить user claims")
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
		return
	}

	// отзыв access - токена
	accessJti := claims.ID
	if _, err := storage.RevokeAccessJwtByTokenID(DbConnection, accessJti); err != nil {
		log.Error().Err(err).Msgf("не удалось отозвать access-токен. JTI: %s", accessJti)
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
		return
	}

	// извлечение refresh-токена
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		log.Error().Err(err).Msgf("не удалось получить refresh-токен. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "refresh-токен не найден", nil, http.StatusBadRequest)
		return
	}
	refreshToken := cookie.Value

	// валидация refresh-токена
	claims, err = auth.ValidateToken(refreshToken)
	if err != nil {
		log.Error().Err(err).Msgf("не валидный refresh-токен. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "не валидный refresh-токен", nil, http.StatusBadRequest)
		return
	}

	refreshJti := claims.ID
	if err := storage.RevokeRefreshJwtByTokenID(DbConnection, refreshJti); err != nil {
		log.Error().Err(err).Msgf("не удалось отозвать refresh-токен. JTI: %s", accessJti)
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
		return
	}

	log.Info().Msgf("Успешный отзыв токенов. ProfileID: %s", claims.Audience[0])
	sendResponse(w, r, "успешный выход", nil, http.StatusOK)
}

/*
	Обработчик отзыва токена

Ожидает на входе параметр id - jti.

Метод: POST

Возвращаемые ошибки:
  - [http.StatusMethodNotAllowed] - неподдерживаемый метод
  - [http.StatusBadRequest] - попытка отзыва токена без id или по не найденному id
  - [http.StatusConflict] - токен не является ни access- ни refresh-токеном
  - [http.StatusOK] - токен успешно отозван
*/
func RevokeHandler(w http.ResponseWriter, r *http.Request) {
	const idField = "id"

	// валидация метода
	if r.Method != http.MethodPost {
		log.Error().Msgf("некорректный HTTP метод. URL: %s", r.URL)
		sendResponse(w, r, "метод не поддерживается", nil, http.StatusMethodNotAllowed)
		return
	}
	if !r.URL.Query().Has(idField) {
		log.Error().Msgf("Попытка отзыва токена без указанного id. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "некорректные параметры запроса", nil, http.StatusBadRequest)
		return
	}
	// получение JTI и отзыв токена
	tokenId := r.URL.Query().Get(idField)

	_, accessTokenErr := storage.RevokeAccessJwtByTokenID(DbConnection, tokenId)
	refreshTokenErr := storage.RevokeRefreshJwtByTokenID(DbConnection, tokenId)
	if accessTokenErr != nil && refreshTokenErr != nil {
		log.Error().Err(accessTokenErr).Err(refreshTokenErr).Msgf("JTI не указывает ни на access-токен, ни на refresh-токен")
		sendResponse(w, r, "не удалось отозвать токен", nil, http.StatusConflict)
		return
	}

	sendResponse(w, r, "токен успешно отозван", nil, http.StatusOK)
}

/*
	Обработчик обновления токена

Метод: POST

Возвращаемые ошибки:
  - [http.StatusMethodNotAllowed] - неподдерживаемый метод
  - [http.StatusBadRequest] - не найден refresh-токен
  - [http.StatusForbidden] - не валидный, отозванный refresh-токен или учётная запись заблокирована
  - [http.StatusInternalServerError] - ошибка при генерации access-токена
  - [http.StatusCreated] - успешное обновление access-токена

При успешной авторизации возвращается JSON-тело с полем access_token
*/
func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	// валидация метода
	if r.Method != http.MethodPost {
		log.Error().Msgf("некорректный HTTP метод. URL: %s", r.URL)
		sendResponse(w, r, "метод не поддерживается", nil, http.StatusMethodNotAllowed)
		return
	}

	// извлечение refresh-токена
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		log.Error().Err(err).Msgf("не удалось получить refresh-токен. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "refresh-токен не найден", nil, http.StatusBadRequest)
		return
	}
	refreshToken := cookie.Value

	// валидация токена
	claims, err := auth.ValidateToken(refreshToken)
	if err != nil {
		log.Error().Err(err).Msgf("не валидный refresh-токен. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "не валидный refresh-токен", nil, http.StatusForbidden)
		return
	}
	if storage.IsRefreshTokenRevoked(DbConnection, claims.ID) {
		log.Error().Err(err).Msgf("попытка доступа по отозванному refresh-токену. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "не валидный refresh-токен", nil, http.StatusForbidden)
		return
	}

	// проверка учётной записи
	profileId := claims.Audience[0]
	credentials, err := storage.GetCredentialsByProfileId(DbConnection, profileId)
	if err != nil {
		log.Error().Err(err).Msgf("запись о пользователе не найдена. ProfileID: %s", profileId)
		sendResponse(w, r, "не валидный refresh-токен", nil, http.StatusForbidden)
		return
	}
	if credentials.IsBlocked == 1 {
		sendResponse(w, r, "не удалось выдать access-токен", nil, http.StatusForbidden)
		if _, err := storage.DeleteJwtByProfileID(DbConnection, profileId); err != nil {
			log.Error().Err(err).Msgf("не удалось удалить refresh-токен пользователя. ProfileID: %s", profileId)
		}
	}

	// выдача нового access-токена
	accessToken, _, err := auth.GenerateToken(profileId, false)
	if err != nil {
		log.Error().Err(err).Msgf("ошибка при генерации нового access-токена по refresh-токену")
		sendResponse(w, r, "не удалось выдать access-токен", nil, http.StatusForbidden)
		return
	}

	sendResponse(w, r, "успешное обновление access-токена", map[string]string{"access_token": accessToken}, http.StatusCreated)
}

/*
	Функция промежуточной проверки доступа к ресурсу

Выполняет проверку наличия и валидацию access-токена + проверка статуса учётной записи.
*/
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if strings.TrimSpace(tokenStr) == "" || len(tokenStr) < 8 {
			log.Info().Msgf("попытка доступа без токена. IP: %s", r.RemoteAddr)
			sendResponse(w, r, "длина токена некорректна", nil, http.StatusUnauthorized)
			return
		}
		token := tokenStr[7:]
		claims, err := auth.ValidateToken(token)
		if err != nil {
			log.Error().Err(err).Msgf("попытка доступа с невалидным токеном. IP: %s", r.RemoteAddr)
			sendResponse(w, r, "не удалось получить доступ", nil, http.StatusUnauthorized)
			return
		}

		if isBlocked := storage.IsBlockedByProfileID(DbConnection, claims.Audience[0]); isBlocked {
			log.Error().Err(err).Msgf("попытка доступа от заблокированного пользователя. IP: %s", r.RemoteAddr)
			sendResponse(w, r, "не удалось получить доступ", nil, http.StatusUnauthorized)
			if _, err := storage.RevokeAccessJwtByTokenID(DbConnection, claims.ID); err != nil {
				log.Error().Err(err).Msgf("Не удалось отозвать access-токен. TokenID: %s", claims.ID)
			}
			return
		}
		ctx := context.WithValue(r.Context(), "user_claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
