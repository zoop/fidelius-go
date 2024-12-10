package decryption

import "github.com/zoop/fidelius-go/utils"

type decryptionHandler struct {
	Curve *utils.Curve
}

/* -------------------------------------------------------------------------- */
/*                              DecryptionHandler                             */
/* -------------------------------------------------------------------------- */
func Handler(curve *utils.Curve) *decryptionHandler {
	controller := &decryptionHandler{
		Curve: curve,
	}
	return controller
}
