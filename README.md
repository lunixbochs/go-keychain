go-keychain
====

A simple interface for using the operating system's keychain to store and retrieve passwords.

Currently only supports OS X.

Usage
----

```Go
import "github.com/lunixbochs/go-keychain"

func main() {
  keychain.Add("test service", "username", "password")
  keychain.Find("test service", "username") == "password"
  keychain.Remove("test service", "username")
}
```
