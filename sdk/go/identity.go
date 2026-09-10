package farcast

// AppName returns this application's name: FARCAST_APP_NAME inside an
// instance, and off-instance the executable's base name (or "unknown").
//
// It exists as an accessor rather than as a configuration key because Config
// refuses the platform's namespace, and an application that cannot learn its
// own name would have no answer at all — see Reserved. It is also the honest
// place for the fallback: off-instance there is no such variable, and a
// configuration getter that invented one would be reporting a value the
// environment does not hold.
func AppName() string { return appName() }

// InstanceID returns the instance this application is running in, or "local"
// off-instance.
//
// Both are ambient identity: read from the environment, stamped on every log
// record, and constant for the life of the process.
func InstanceID() string { return instanceID() }
