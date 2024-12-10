package keypairgen

import "github.com/zoop/fidelius-go/utils"

type keyPairGenHandler struct {
	Curve *utils.Curve
}

/* -------------------------------------------------------------------------- */
/*                              KeyPairGenHandler                             */
/* -------------------------------------------------------------------------- */
func Handler(curve *utils.Curve) *keyPairGenHandler {
	handler := &keyPairGenHandler{
		Curve: curve,
	}
	return handler
}
