package model

type RegisterDto struct {
	Name       string `json:"name" validate:"required,alphaunicode,min=2,max=50"`
	Surname    string `json:"surname" validate:"required,alphaunicode,min=2,max=50"`
	Patronymic string `json:"patronymic,omitempty" validate:"omitempty,alphaunicode,min=2,max=50"`
	Login      string `json:"login" validate:"required,alphanum,min=5,max=20"`
	Password   string `json:"password" validate:"required,min=8,max=64"`
}

type LoginDto struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
