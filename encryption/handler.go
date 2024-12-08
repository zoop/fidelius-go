package encryption

/* -------------------------------------------------------------------------- */
/*                              EncryptionHandler                             */
/* -------------------------------------------------------------------------- */
type encryptionHandler struct{}

func Handler() *encryptionHandler {
	controller := &encryptionHandler{}
	return controller
}
