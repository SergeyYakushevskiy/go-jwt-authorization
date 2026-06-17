package model

type Profile struct {
	ID         string `reindex:"id,,pk,uuid" json:"id"`
	Name       string `reindex:"name,,collate_utf8" json:"name"`
	Surname    string `reindex:"surname,hash,,collate_utf8" json:"surname"`
	Patronymic string `reindex:"patronymic,hash,collate_utf8" json:"patronymic,omitempty"`
	CreatedAt  int64  `reindex:"created_at,tree" json:"created_at"`
}

/*
	Аутентификационные данные пользователя

поле [Credentials.IsBlocked] принимает два значения:
  - 0 - пользователю разрешён доступ;
  - 1 - пользователю запрещён доступ
*/
type Credentials struct {
	ID           int64  `reindex:"id,hash,pk" json:"id"`
	ProfileID    string `reindex:"profile_id,,uuid" json:"profile_id"`
	Login        string `reindex:"login,hash,collate_utf8" json:"login"`
	PasswordHash string `reindex:"password_hash,-,collate_utf8" json:"password_hash"`
	UpdatedAt    int64  `reindex:"updated_at,tree" json:"updated_at,omitempty"`
	IsBlocked    int8   `reindex:"is_blocked,-" json:"is_blocked"`
}

type Jwt struct {
	ID         int64  `reindex:"id,hash,pk" json:"id"`
	ProfileID  string `reindex:"profile_id,,uuid" json:"profile_id"`
	RefreshJti string `reindex:"refresh_jti" json:"refresh_jti"`
	Device     string `reindex:"device,hash,collate_utf8" json:"device"`
	IsRevoked  uint8  `reindex:"is_revoked,-" json:"is_revoked"`
	CreatedAt  int64  `reindex:"created_at,tree" json:"created_at"`
	IP         string `reindex:"ip,hash,,collate_numeric" json:"ip"`
}

type JwtBlacklist struct {
	ID        int64  `reindex:"id,hash,pk" json:"id"`
	AccessJti string `reindex:"access_jti,hash,collate_numeric" json:"access_jti"`
}
