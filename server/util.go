package server

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

/*
	Функция отправки ответа

Тип ответа: JSON

При неудачной отправке вернёт [http.StatusInternalServerError].
Если запрос пустой, то отправка не произойдёт
*/
func sendResponse(w http.ResponseWriter, r *http.Request, status string, message any, code int) {
	if code == 0 {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	data, err := json.Marshal(Response{Status: status, Message: message})
	if err != nil {
		http.Error(w, "ошибка преобразования данных для отправки", http.StatusInternalServerError)
		log.Error().Err(err).Msgf("ошибка преобразования данных для отправки. URL: %s", r.URL)
		return
	}
	if _, err := w.Write(data); err != nil {
		http.Error(w, "ошибка записи данных в буфер для отправки", http.StatusInternalServerError)
		log.Error().Err(err).Msgf("ошибка отправки данных. URL: %s", r.URL)
		return
	}
}
