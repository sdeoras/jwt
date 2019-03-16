# jwt

## about
This repo is a simple wrapper over jwt api to allow easy authentication for http handle functions.
The primary use case is for providing an jwt authentication layer for google cloud functions. 

## server side
create an instance on the server side to validate incoming http.Request

http handlers should be written without any jwt logic
```go
func myHttpHandleFunc(w http.ResponseWriter, r *http.Request) {
	// do something...
}
```

then create an instance of jwt manager requesting it to enforce lifespan check
```go
import "github.com/sdeoras/jwt"

func main() {
	mgr := jwt.NewManager("yourSecretKey", jwt.EnforceExpiration())
	
	// and wrap http handl func
	
	f := mgr.NewHTTPHandler(myHttpHandleFunc)
	
	// pass f to your http routers
}
```

## client side
create an instance on the client side to build http.Request with jwt token embedded in it.

```go
mgr := jwt.NewManager("yourSecretKey", jwt.SetLifeSpan(time.Second))

// call NewHTTPRequest to create a new http request
```

see tests for more details