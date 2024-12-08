package decryption

type decryptionHandler struct{}

/* -------------------------------------------------------------------------- */
/*                              DecryptionHandler                             */
/* -------------------------------------------------------------------------- */
func Handler() *decryptionHandler {
	controller := &decryptionHandler{}
	return controller
}
