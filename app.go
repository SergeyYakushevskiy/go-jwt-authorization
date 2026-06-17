package main

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/SergeyYakushevskiy/jwt-authorization/auth"
	"github.com/SergeyYakushevskiy/jwt-authorization/model"
	"github.com/SergeyYakushevskiy/jwt-authorization/server"
	"github.com/SergeyYakushevskiy/jwt-authorization/storage"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"gitverse.ru/uzer_007/gogost/v2/gost34112012256"
)

const (
	// конфигурация
	confFilePath  = "./config.json"
	fileSeparator = string(filepath.Separator)

	// логирование
	logFileName = "log.json"

	//jwt
	jwtSecretFilePath = "./jwt.key"
	jwtSecretLenth    = 64 // Байт
)

var (
	incorrectSecretFileErr = errors.New("некорректное содержимое файла секрета")
)

/*
	Функция конфигурации логирования

Задаются уровни логирования для файла и консоли, указывается папка для хранения файлов логов
*/
func setup_logging(logging *model.LoggingConfig) (*os.File, error) {
	// настройки логирования в файл
	logPath := strings.Join([]string{logging.Dir, logFileName}, fileSeparator)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	// настройка логирования в консоль
	logConsoleLevel, err := zerolog.ParseLevel(logging.ConsoleLevel)
	if err != nil {
		return nil, errors.New("ошибка парсинга уровня логирования: " + err.Error())
	}
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "02.01.2006 15:04:05",
		NoColor:    true,
	}
	consoleFiltered := zerolog.FilteredLevelWriter{
		Writer: zerolog.LevelWriterAdapter{Writer: consoleWriter},
		Level:  logConsoleLevel,
	}

	// аггрегация в единый логгер
	multiWriter := zerolog.MultiLevelWriter(&consoleFiltered, logFile)
	logger := zerolog.New(multiWriter).With().Timestamp().Caller().Logger()

	log.Logger = logger
	return logFile, nil
}

/*
	Функция инициализации jwt-секрета

Работает по следующему алгоритму:
  - если файла по заданному пути нет, то создать пустой файл, сгенерировать ключ и записать в файл;
  - если файл есть, но содержимое не соответствует правилам, то вернуть [incorrectSecretFileErr];
  - если файл есть, и содержимое соответствует правилам, то вернуть содержимое файла.
*/
func initJwtSecret() ([]byte, error) {
	// открытие / создание файла
	var secret []byte = make([]byte, 0, jwtSecretLenth)
	info, err := os.Stat(jwtSecretFilePath)
	// если файл пуст
	if os.IsNotExist(err) {
		secret = generateJwtSecret()
		if err := os.WriteFile(jwtSecretFilePath, secret, 0600); err != nil {
			return nil, err
		}
		log.Debug().Msg("файл секрета пуст, сгенерирован новый секрет")
		return secret, nil
	}
	if err != nil {
		return nil, err
	}

	// если не пуст, но размер содержимого несоответствующий
	if info.Size() != jwtSecretLenth {
		return nil, incorrectSecretFileErr
	}

	// штатный случай
	secret, err = os.ReadFile(jwtSecretFilePath)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

/*
Функция генерации секрета
*/
func generateJwtSecret() []byte {
	const byteCount = 32
	var (
		keywords []byte = make([]byte, 0, byteCount)
		salt     []byte = make([]byte, 0, byteCount)
	)
	rand.Read(keywords)
	rand.Read(salt)
	jwtKey, _ := pbkdf2.Key(gost34112012256.New, string(keywords), salt, 10, jwtSecretLenth)
	return jwtKey
}

func main() {
	// регистрация сигналов завершения работы
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGTSTP)
	defer stop()

	// инициализация конфига
	var (
		config       model.Config
		tokenManager *auth.TokenManager
	)
	conf_file, err := os.Open(confFilePath)
	if err != nil {
		log.Error().Err(err).Msg("ошибка доступа к файлу конфигурации")
		return
	}
	defer conf_file.Close()
	if err := json.NewDecoder(conf_file).Decode(&config); err != nil {
		log.Error().Err(err).Msg("ошибка считывания конфигурации")
		return
	}

	// конфигурация логирования
	logFile, err := setup_logging(config.Logging)
	if err != nil {
		log.Error().Err(err).Msg("ошибка настройки логирования")
		return
	}
	defer logFile.Close()

	// инициализация адаптера БД
	db, err := storage.New(config.Db)
	if err != nil {
		log.Error().Err(err).Msg("ошибка инициализации адаптера БД")
		return
	}
	defer db.Close()
	server.Init(db)

	// инициализация jwt-секрета
	jwtSecret, err := initJwtSecret()
	if err != nil {
		log.Error().Err(err).Msg("ошибка инициализации JWT-секрета")
		return
	}
	tokenManager, err = auth.NewTokenManager(jwtSecret, config.Jwt.RefreshTokenExpired, config.Jwt.AccessTokenExpired)
	if err != nil {
		log.Error().Err(err).Msg("ошибка валидации JWT-секрета")
	}
	auth.TokenMgr = tokenManager

	// инициализация сервера
	err = server.Start(ctx, server.New(config.Http))
	if err != nil {
		log.Error().Err(err).Msg("ошибка работы сервера")
		return
	}
	log.Info().Msg("приложение остановлено")
}
