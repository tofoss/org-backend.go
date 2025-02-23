package requests

type Register struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
