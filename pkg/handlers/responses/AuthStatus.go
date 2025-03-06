package responses

type AuthStatus struct {
	LoggedIn bool   `json:"loggedIn"`
	Username string `json:"username"`
	UserID   string `json:"userID"`
}
