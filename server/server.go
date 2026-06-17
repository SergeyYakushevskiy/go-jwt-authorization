package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/SergeyYakushevskiy/jwt-authorization/model"
	"github.com/rs/zerolog/log"
)

const (
	shutdownTimeout = 5 * time.Second

	serviceEndpoint  = "/api"
	registerEndpoint = serviceEndpoint + "/register"
	loginEndpoint    = serviceEndpoint + "/login"
	refreshEndpoint  = serviceEndpoint + "/refresh"
	profileEndpoint  = serviceEndpoint + "/profile"
	revokeEndpoint   = serviceEndpoint + "/revoke"
	logoutEndpoint   = serviceEndpoint + "/logout"
	sessionsEndpoint = serviceEndpoint + "/sessions"
)

func New(config *model.HttpConfig) *http.Server {
	var server *http.Server
	mux := http.NewServeMux()
	address := config.Host + ":" + strconv.Itoa(int(config.Port))

	// обёртка маршрутов
	mux.HandleFunc(registerEndpoint, RegisterHandler)
	mux.HandleFunc(loginEndpoint, LoginHandler)
	mux.HandleFunc(refreshEndpoint, RefreshHandler)
	mux.Handle(revokeEndpoint, AuthMiddleware(http.HandlerFunc(RevokeHandler)))
	mux.Handle(logoutEndpoint, AuthMiddleware(http.HandlerFunc(LogoutHandler)))
	mux.Handle(profileEndpoint, AuthMiddleware(http.HandlerFunc(ProfileHandler)))
	mux.Handle(sessionsEndpoint, AuthMiddleware(http.HandlerFunc(SessionsHandler)))

	server = &http.Server{
		Addr:    address,
		Handler: mux,
	}

	return server
}

func Start(ctx context.Context, server *http.Server) error {
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("ошибка запуска сервера: ")
		}
	}()
	log.Info().Msg("сервер запущен по адресу " + server.Addr)
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return err
	}

	select {
	case <-shutdownCtx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
