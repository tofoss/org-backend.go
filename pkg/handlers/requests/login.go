package requests

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
