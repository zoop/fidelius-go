package keypairgen

type keyPairGenHandler struct{}

/* -------------------------------------------------------------------------- */
/*                              KeyPairGenHandler                             */
/* -------------------------------------------------------------------------- */
func Handler() *keyPairGenHandler {
	handler := &keyPairGenHandler{}
	return handler
}
