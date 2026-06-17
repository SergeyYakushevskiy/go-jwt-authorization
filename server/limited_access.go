package server

import (
	"net/http"

	"github.com/SergeyYakushevskiy/jwt-authorization/storage"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

/*
	Обработчик доступа к данным профиля

Метод: GET

Возвращаемые коды:
  - [http.StatusMethodNotAllowed] - не поддерживаемый метод
  - [http.StatusBadRequest] - попытка доступа без id или по не найденному id
  - [http.StatusInternalServerError] - ошибка получения user claims
  - [http.StatusOK] - успешный доступ

При успешной авторизации возвращается JSON-тело с полями
  - surname
  - name
  - patronymic
*/
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	const idField = "id"

	// валидация метода
	if r.Method != http.MethodGet {
		log.Error().Msgf("некорректный HTTP метод. URL: %s", r.URL)
		sendResponse(w, r, "метод не поддерживается", nil, http.StatusMethodNotAllowed)
		return
	}
	if !r.URL.Query().Has(idField) {
		log.Error().Msgf("Попытка доступа без указанного id. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "некорректные параметры запроса", nil, http.StatusBadRequest)
		return
	}
	// проверка владения токеном
	profileId := r.URL.Query().Get(idField)
	claims, ok := r.Context().Value("user_claims").(*jwt.RegisteredClaims)
	if !ok || len(claims.Audience[0]) < 1 {
		log.Error().Msgf("не удалось получить user claims из контекста. ProfileID: %s", profileId)
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
		return
	}
	if profileId != claims.Audience[0] {
		log.Error().Msgf("попытка доступа под чужим access-токеном. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "не удалось получить доступ", nil, http.StatusUnauthorized)
		return
	}

	// получение данных
	profile, err := storage.GetProfileById(DbConnection, profileId)
	if err != nil {
		log.Error().Err(err).Msgf("попытка доступа по неизвестному id пользователя. ProfileID: %s, IP: %s", profileId, r.RemoteAddr)
		sendResponse(w, r, "пользователь не найден", nil, http.StatusBadRequest)
		return
	}

	// отправка ответа
	responseMsg := map[string]string{"surname": profile.Surname, "name": profile.Name, "patronymic": profile.Patronymic}
	sendResponse(w, r, "", responseMsg, http.StatusOK)
}

/*
	Обработчик получения всех активных сессий пользователя

Ожидает параметр id - идентификатор пользователя.

Метод: GET

Возвращаемые коды:
  - [http.StatusMethodNotAllowed] - не поддерживаемый метод
  - [http.StatusBadRequest] - попытка доступа без id или по не найденному id
  - [http.StatusInternalServerError] - ошибка получения user claims
  - [http.StatusOK] - успешное получение списка сессий

При успешной авторизации возвращается JSON-тело со списком [][storage.Session]
*/
func SessionsHandler(w http.ResponseWriter, r *http.Request) {
	const idField = "id"

	// валидация метода
	if r.Method != http.MethodGet {
		log.Error().Msgf("некорректный HTTP метод. URL: %s", r.URL)
		sendResponse(w, r, "метод не поддерживается", nil, http.StatusMethodNotAllowed)
		return
	}
	if !r.URL.Query().Has(idField) {
		log.Error().Msgf("Попытка доступа без указанного id. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "некорректные параметры запроса", nil, http.StatusBadRequest)
		return
	}
	// проверка владения токеном
	profileId := r.URL.Query().Get(idField)
	claims, ok := r.Context().Value("user_claims").(*jwt.RegisteredClaims)
	if !ok || len(claims.Audience[0]) < 1 {
		log.Error().Msgf("не удалось получить user claims из контекста. ProfileID: %s", profileId)
		sendResponse(w, r, "ошибка на стороне сервера", nil, http.StatusInternalServerError)
		return
	}
	if profileId != claims.Audience[0] {
		log.Error().Msgf("попытка доступа под чужим access-токеном. IP: %s", r.RemoteAddr)
		sendResponse(w, r, "не удалось получить доступ", nil, http.StatusUnauthorized)
		return
	}

	// получение данных

	sessions, err := storage.GetSessionsByProfileId(DbConnection, profileId)
	if err != nil {
		log.Error().Err(err).Msgf("попытка доступа по неизвестному id пользователя. ProfileID: %s, IP: %s", profileId, r.RemoteAddr)
		sendResponse(w, r, "пользователь не найден", nil, http.StatusBadRequest)
		return
	}

	// отправка ответа
	sendResponse(w, r, "", sessions, http.StatusOK)
}
