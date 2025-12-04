function startTLSKeyLogger(e, o) {
	console.log("start----");
	const t = new NativeCallback((function(e, o) {
		console.log(new NativePointer(o).readCString())
	}), "void", ["pointer", "pointer"]);
	Interceptor.attach(e, {
		onLeave: function(e) {
			const n = new NativePointer(e);
			new NativeFunction(o, "void", ["pointer", "pointer"])(n, t)
		}
	})
}
startTLSKeyLogger(Module.findExportByName("libssl.so", "SSL_CTX_new"), Module.findExportByName("libssl.so", "SSL_CTX_set_keylog_callback"));
