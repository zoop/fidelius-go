package encryption

import "github.com/zoop/fidelius-go/utils"

/* -------------------------------------------------------------------------- */
/*                              EncryptionHandler                             */
/* -------------------------------------------------------------------------- */
type encryptionHandler struct {
	Curve *utils.Curve
}

func Handler(curve *utils.Curve) *encryptionHandler {
	controller := &encryptionHandler{
		Curve: curve,
	}
	return controller
}
